"""
MOLE DNS over TLS Service - Encrypted DNS with ad-blocking
"""

import asyncio
import ssl
import struct
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, TYPE_CHECKING

from ..utils import log

if TYPE_CHECKING:
    from ..config import Config


# DNS over TLS upstream providers: (ip, port, sni_hostname)
DOT_PROVIDERS = {
    'cloudflare': ('1.1.1.1', 853, 'cloudflare-dns.com'),
    'cloudflare-family': ('1.1.1.3', 853, 'family.cloudflare-dns.com'),  # Blocks malware + adult content
    'quad9': ('9.9.9.9', 853, 'dns.quad9.net'),              # Blocks malware
    'quad9-unsecured': ('9.9.9.10', 853, 'dns.quad9.net'),   # No blocking
    'google': ('8.8.8.8', 853, 'dns.google'),
}

# Blocklist URLs (hosts file format)
BLOCKLIST_URLS = {
    'ads': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts',
    'malware': 'https://urlhaus.abuse.ch/downloads/hostfile/',
    'tracking': 'https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt',
}


class DNSProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for DNS queries"""

    def __init__(self, server: 'DOTServer'):
        self.server = server
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        """Handle incoming DNS query"""
        asyncio.create_task(self._handle_query(data, addr))

    async def _handle_query(self, data: bytes, addr: tuple):
        """Process DNS query and send response"""
        try:
            response = await self.server.resolve(data)
            if response and self.transport:
                self.transport.sendto(response, addr)
        except Exception as e:
            log.debug(f"DNS query error: {e}")


class DOTServer:
    """DNS over TLS server with filtering and caching support"""

    def __init__(self, config: "Config", netns: str):
        self.config = config
        self.netns = netns
        self.bind = config.dot_bind
        self.port = config.dot_port
        self.upstream_ip, self.upstream_port, self.upstream_sni = self._get_upstream()
        self.blocked_domains: set = set()
        self._transport = None
        self._protocol = None
        # DNS cache: {(domain, qtype): (response_bytes, expiry_time)}
        self._cache: Dict[Tuple[str, int], Tuple[bytes, float]] = {}
        self._cache_enabled = config.dot_caching
        self._cache_max_ttl = config.dot_cache_ttl  # 0 = use response TTL
        self._blocklist_update_task = None
        self._last_blocklist_update = 0.0

    def _get_upstream(self) -> Tuple[str, int, str]:
        """Get upstream DNS server (IP, port, SNI hostname)"""
        upstream = self.config.dot_upstream.lower()
        if upstream == 'custom':
            custom = self.config.dot_custom_server
            if ':' in custom:
                ip, port = custom.rsplit(':', 1)
                return (ip, int(port), ip)  # Use IP as hostname for custom
            return (custom, 853, custom)
        provider = DOT_PROVIDERS.get(upstream, DOT_PROVIDERS['cloudflare'])
        return provider  # Returns (ip, port, sni_hostname)

    async def start(self):
        """Start the DNS server"""
        # Load blocklists
        await self._load_blocklists()
        self._last_blocklist_update = time.time()

        # Create UDP server
        loop = asyncio.get_event_loop()
        self._transport, self._protocol = await loop.create_datagram_endpoint(
            lambda: DNSProtocol(self),
            local_addr=(self.bind, self.port)
        )
        log.info(f"DNS over TLS server listening on {self.bind}:{self.port}")
        log.info(f"DNS upstream: {self.config.dot_upstream} ({self.upstream_ip}:{self.upstream_port})")
        log.info(f"DNS caching: {'enabled' if self._cache_enabled else 'disabled'}")
        log.info(f"DNS blocking {len(self.blocked_domains)} domains")

        # Start blocklist update task if enabled
        update_period = self.config.dot_update_period
        if update_period > 0:
            log.info(f"DNS blocklist auto-update: every {update_period // 3600}h")
            self._blocklist_update_task = asyncio.create_task(self._blocklist_update_loop())

        # Keep running
        while True:
            await asyncio.sleep(3600)

    async def stop(self):
        """Stop the DNS server"""
        if self._blocklist_update_task:
            self._blocklist_update_task.cancel()
            try:
                await self._blocklist_update_task
            except asyncio.CancelledError:
                pass
        if self._transport:
            self._transport.close()

    async def _blocklist_update_loop(self):
        """Periodically update blocklists"""
        update_period = self.config.dot_update_period
        while True:
            try:
                await asyncio.sleep(update_period)
                log.info("Updating DNS blocklists...")
                old_count = len(self.blocked_domains)
                await self._load_blocklists()
                new_count = len(self.blocked_domains)
                self._last_blocklist_update = time.time()
                log.info(f"DNS blocklists updated: {old_count} -> {new_count} domains")
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Blocklist update error: {e}")

    async def _load_blocklists(self):
        """Load and parse blocklists"""
        blocklists_to_load = []
        if self.config.dot_block_ads:
            blocklists_to_load.append('ads')
        if self.config.dot_block_malware:
            blocklists_to_load.append('malware')
        if self.config.dot_block_tracking:
            blocklists_to_load.append('tracking')

        if not blocklists_to_load:
            return

        # Cache directory
        cache_dir = Path(self.config.state_dir) / 'blocklists'
        cache_dir.mkdir(parents=True, exist_ok=True)

        for name in blocklists_to_load:
            url = BLOCKLIST_URLS.get(name)
            if not url:
                continue

            cache_file = cache_dir / f"{name}.txt"
            content = None

            # Try to download fresh blocklist
            try:
                async with asyncio.timeout(30):
                    proc = await asyncio.create_subprocess_exec(
                        'curl', '-sL', '--max-time', '25', url,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    stdout, _ = await proc.communicate()
                    if proc.returncode == 0 and stdout:
                        content = stdout.decode('utf-8', errors='ignore')
                        # Cache the blocklist
                        cache_file.write_text(content)
                        log.debug(f"Downloaded {name} blocklist")
            except Exception as e:
                log.debug(f"Failed to download {name} blocklist: {e}")

            # Fall back to cached version
            if not content and cache_file.exists():
                content = cache_file.read_text()
                log.debug(f"Using cached {name} blocklist")

            if content:
                self._parse_hosts_file(content)

    def _parse_hosts_file(self, content: str):
        """Parse hosts file format and add domains to blocklist"""
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Hosts file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
            parts = line.split()
            if len(parts) >= 2:
                domain = parts[1].lower()
                # Skip local entries
                if domain not in ('localhost', 'localhost.localdomain', 'local', 'broadcasthost'):
                    self.blocked_domains.add(domain)

    async def resolve(self, query: bytes) -> Optional[bytes]:
        """Resolve DNS query, blocking or forwarding as needed"""
        try:
            # Parse domain and query type from query
            domain = self._extract_domain(query)
            qtype = self._extract_qtype(query) if self._cache_enabled else 0

            if domain:
                # Check blocklist first (no point caching blocked domains)
                if self._is_blocked(domain):
                    log.debug(f"DNS blocked: {domain}")
                    return self._make_nxdomain_response(query)

                # Check cache
                if self._cache_enabled:
                    cache_key = (domain, qtype)
                    cached = self._cache.get(cache_key)
                    if cached:
                        response, expiry = cached
                        if time.time() < expiry:
                            log.debug(f"DNS cache hit: {domain}")
                            # Update transaction ID to match query
                            return query[:2] + response[2:]
                        else:
                            # Expired, remove from cache
                            del self._cache[cache_key]

            # Forward to upstream via TLS
            response = await self._query_upstream(query)

            # Cache successful response
            if response and self._cache_enabled and domain:
                ttl = self._extract_response_ttl(response)
                # Apply max TTL cap if configured
                if self._cache_max_ttl > 0:
                    ttl = min(ttl, self._cache_max_ttl)
                cache_key = (domain, qtype)
                self._cache[cache_key] = (response, time.time() + ttl)
                log.debug(f"DNS cached: {domain} (TTL={ttl}s)")

                # Simple cache cleanup: remove expired entries periodically
                if len(self._cache) > 1000:
                    now = time.time()
                    self._cache = {k: v for k, v in self._cache.items() if v[1] > now}

            return response

        except Exception as e:
            log.debug(f"DNS resolve error: {e}")
            return None

    def _extract_domain(self, query: bytes) -> Optional[str]:
        """Extract domain name from DNS query"""
        try:
            # Skip header (12 bytes)
            pos = 12
            labels = []

            while pos < len(query):
                length = query[pos]
                if length == 0:
                    break
                if length >= 64:  # Compression pointer, stop here
                    break
                pos += 1
                labels.append(query[pos:pos + length].decode('utf-8', errors='ignore'))
                pos += length

            return '.'.join(labels).lower() if labels else None
        except Exception:
            return None

    def _extract_qtype(self, query: bytes) -> int:
        """Extract query type from DNS query (A=1, AAAA=28, etc.)"""
        try:
            # Skip header (12 bytes) and find end of domain name
            pos = 12
            while pos < len(query) and query[pos] != 0:
                length = query[pos]
                if length >= 64:  # Compression pointer
                    pos += 2
                    break
                pos += 1 + length
            else:
                pos += 1  # Skip null terminator

            # QTYPE is 2 bytes after domain name
            if pos + 2 <= len(query):
                return struct.unpack('!H', query[pos:pos + 2])[0]
            return 0
        except Exception:
            return 0

    def _extract_response_ttl(self, response: bytes) -> int:
        """Extract minimum TTL from DNS response for cache expiry"""
        try:
            # Parse header
            if len(response) < 12:
                return 300  # Default 5 minutes

            ancount = struct.unpack('!H', response[6:8])[0]
            if ancount == 0:
                return 300  # No answers, use default

            # Skip header and question section
            pos = 12
            # Skip question name
            while pos < len(response) and response[pos] != 0:
                length = response[pos]
                if length >= 64:  # Compression pointer
                    pos += 2
                    break
                pos += 1 + length
            else:
                pos += 1  # Skip null terminator
            pos += 4  # Skip QTYPE and QCLASS

            # Parse answer records to find minimum TTL
            min_ttl = 86400  # Default max 24 hours
            for _ in range(ancount):
                if pos >= len(response):
                    break
                # Skip name (may be compressed)
                if response[pos] >= 192:  # Compression pointer
                    pos += 2
                else:
                    while pos < len(response) and response[pos] != 0:
                        pos += 1 + response[pos]
                    pos += 1

                if pos + 10 > len(response):
                    break

                # TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
                ttl = struct.unpack('!I', response[pos + 4:pos + 8])[0]
                rdlength = struct.unpack('!H', response[pos + 8:pos + 10])[0]
                min_ttl = min(min_ttl, ttl)
                pos += 10 + rdlength

            return max(60, min_ttl)  # At least 60 seconds
        except Exception:
            return 300  # Default 5 minutes on error

    def _is_blocked(self, domain: str) -> bool:
        """Check if domain or parent domain is blocked"""
        # Check exact match
        if domain in self.blocked_domains:
            return True

        # Check parent domains (e.g., ads.example.com -> example.com)
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.blocked_domains:
                return True

        return False

    def _make_nxdomain_response(self, query: bytes) -> bytes:
        """Create NXDOMAIN response for blocked domains"""
        # Copy transaction ID
        response = bytearray(query[:2])
        # Flags: QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=3 (NXDOMAIN)
        response.extend([0x81, 0x83])
        # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        response.extend([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        # Copy question section
        response.extend(query[12:])
        return bytes(response)

    async def _query_upstream(self, query: bytes) -> Optional[bytes]:
        """Forward query to upstream DNS over TLS"""
        try:
            # Create TLS context
            ctx = ssl.create_default_context()

            # Connect to upstream with SNI hostname for certificate validation
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.upstream_ip, self.upstream_port,
                    ssl=ctx, server_hostname=self.upstream_sni
                ),
                timeout=10.0
            )

            try:
                # DNS over TLS uses length-prefixed messages
                writer.write(struct.pack('!H', len(query)) + query)
                await writer.drain()

                # Read response
                length_data = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
                length = struct.unpack('!H', length_data)[0]
                response = await asyncio.wait_for(reader.readexactly(length), timeout=10.0)

                return response

            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        except asyncio.TimeoutError:
            log.debug("DNS upstream timeout")
            return None
        except Exception as e:
            log.debug(f"DNS upstream error: {e}")
            return None

    def get_stats(self) -> dict:
        """Get DNS server statistics"""
        return {
            "enabled": self.config.dot_enabled,
            "upstream": self.config.dot_upstream,
            "upstream_ip": self.upstream_ip,
            "upstream_port": self.upstream_port,
            "blocked_domains": len(self.blocked_domains),
            "cache_enabled": self._cache_enabled,
            "cache_size": len(self._cache),
            "last_blocklist_update": self._last_blocklist_update,
        }
