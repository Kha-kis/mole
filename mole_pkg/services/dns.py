"""
MOLE DNS over TLS Service - Encrypted DNS with ad-blocking
"""

import asyncio
import struct
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, TYPE_CHECKING

from ..utils import log
from .dns_upstream import (
    DOT_PROVIDERS,
    UpstreamExhausted,
    UpstreamPool,
    resolve_upstream,
)

if TYPE_CHECKING:
    from ..config import Config

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
        # Primary upstream info kept for backward-compatible callers/tests that
        # read these attributes. The pool below is what actually serves queries
        # and may failover across multiple upstreams.
        upstreams = self._resolve_upstream_list()
        primary_name = upstreams[0]
        self.upstream_ip, self.upstream_port, self.upstream_sni = resolve_upstream(
            primary_name,
            getattr(config, 'dot_custom_server', '') or '',
            getattr(config, 'dot_custom_sni', '') or '',
        )
        self.blocked_domains: set = set()
        self._transport = None
        self._protocol = None
        # DNS cache: {(domain, qtype): (response_bytes, expiry_time)}
        self._cache: Dict[Tuple[str, int], Tuple[bytes, float]] = {}
        self._cache_enabled = config.dot_caching
        self._cache_max_ttl = config.dot_cache_ttl  # 0 = use response TTL
        self._blocklist_update_task = None
        self._last_blocklist_update = 0.0
        # In-flight singleflight map: (domain, qtype) -> Future[response_bytes].
        # Followers await the same upstream query instead of stampeding.
        self._in_flight: Dict[Tuple[str, int], asyncio.Future] = {}
        # Stats counters. Kept as a plain dict; asyncio single-threaded so
        # += is safe. Exposed via get_stats() / /v1/dns.
        self._stats: Dict[str, int] = {
            'queries_total': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'in_flight_peak': 0,
            'singleflight_collapses': 0,
            'blocked': 0,
            'upstream_queries': 0,
            'upstream_errors': 0,
            'retries': 0,
            'failovers': 0,
            'resolve_errors': 0,
        }
        # Upstream pool. Created in __init__ (cheap — no sockets open yet);
        # real TLS connections are lazy on first query.
        custom_server = getattr(config, 'dot_custom_server', '') or ''
        if not isinstance(custom_server, str):
            custom_server = ''
        custom_sni = getattr(config, 'dot_custom_sni', '') or ''
        if not isinstance(custom_sni, str):
            custom_sni = ''
        self._pool = UpstreamPool(
            upstreams=upstreams,
            custom_server=custom_server,
            custom_sni=custom_sni,
            pool_size=self._coerce_int(getattr(config, 'dot_pool_size', 2), 2),
            query_timeout=self._coerce_float(getattr(config, 'dot_query_timeout', 2.0), 2.0),
            query_retries=self._coerce_int(getattr(config, 'dot_query_retries', 2), 2),
            retry_backoff_ms=self._coerce_int(getattr(config, 'dot_retry_backoff_ms', 200), 200),
            stats=self._stats,
        )

    def _resolve_upstream_list(self) -> list:
        """Return the configured upstream list as a clean list of names.

        Prefers config.dot_upstreams (new, list/tuple) when it's an actual
        list/tuple of strings; otherwise splits config.dot_upstream (old, str)
        on commas. Tolerant of unexpected attribute types to keep test mocks
        and third-party config shims from blowing up.
        """
        explicit = getattr(self.config, 'dot_upstreams', None)
        if isinstance(explicit, (list, tuple)) and explicit:
            return [str(u).strip() for u in explicit if str(u).strip()] or ['cloudflare']
        raw = getattr(self.config, 'dot_upstream', 'cloudflare')
        if not isinstance(raw, str) or not raw:
            return ['cloudflare']
        return [u.strip() for u in raw.split(',') if u.strip()] or ['cloudflare']

    @staticmethod
    def _coerce_int(val, default: int) -> int:
        try:
            return int(val)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _coerce_float(val, default: float) -> float:
        try:
            return float(val)
        except (TypeError, ValueError):
            return default

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
        # Close upstream pool and fail any still-pending waiters.
        await self._pool.close()

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
        """Resolve a DNS query: blocklist → cache → singleflight upstream.

        Returns response bytes with the caller's xid preserved, or None on
        unrecoverable failure.
        """
        self._stats['queries_total'] += 1
        try:
            if len(query) < 12:
                return None
            client_xid = struct.unpack('!H', query[:2])[0]
            domain = self._extract_domain(query)
            if domain:
                qtype, qclass = self._extract_qtype_qclass(query)
            else:
                qtype, qclass = 0, 0

            if domain:
                if self._is_blocked(domain):
                    self._stats['blocked'] += 1
                    log.debug(f"DNS blocked: {domain}")
                    return self._make_nxdomain_response(query)

                # Key singleflight AND cache on (domain, qtype, qclass) so
                # queries that differ only in qclass (e.g. IN vs CH) don't
                # collapse into one another.
                key = (domain, qtype, qclass)

                if self._cache_enabled:
                    cached = self._cache.get(key)
                    if cached:
                        response, expiry = cached
                        if time.time() < expiry:
                            self._stats['cache_hits'] += 1
                            log.debug(f"DNS cache hit: {domain}")
                            return query[:2] + response[2:]
                        # Expired — drop and fall through to upstream
                        del self._cache[key]
                    # Only count misses when cache was actually consulted,
                    # so hits/(hits+misses) stays a meaningful ratio.
                    self._stats['cache_misses'] += 1

                # Singleflight: if an identical question is already in flight,
                # await its result rather than firing a duplicate upstream query.
                existing = self._in_flight.get(key)
                if existing is not None:
                    self._stats['singleflight_collapses'] += 1
                    try:
                        leader_response = await existing
                    except Exception:
                        return None
                    if leader_response is None:
                        return None
                    return query[:2] + leader_response[2:]

                # Leader path. Register our Future before awaiting so late
                # followers attach to it.
                loop = asyncio.get_event_loop()
                fut: asyncio.Future = loop.create_future()
                self._in_flight[key] = fut
                if len(self._in_flight) > self._stats['in_flight_peak']:
                    self._stats['in_flight_peak'] = len(self._in_flight)
                try:
                    response = await self._forward(query, client_xid)
                    # Store in cache BEFORE resolving the future so any waiter
                    # that wakes up sees a consistent cache+singleflight world.
                    if response and self._cache_enabled:
                        ttl = self._extract_response_ttl(response)
                        if self._cache_max_ttl > 0:
                            ttl = min(ttl, self._cache_max_ttl)
                        self._cache[key] = (response, time.time() + ttl)
                        log.debug(f"DNS cached: {domain} (TTL={ttl}s)")
                        if len(self._cache) > 1000:
                            now = time.time()
                            self._cache = {k: v for k, v in self._cache.items() if v[1] > now}
                    if not fut.done():
                        fut.set_result(response)
                    return response
                except Exception as e:
                    if not fut.done():
                        fut.set_exception(e)
                    raise
                finally:
                    self._in_flight.pop(key, None)

            # Domainless query (unusual) — forward without dedup/cache.
            return await self._forward(query, client_xid)

        except UpstreamExhausted as e:
            self._stats['resolve_errors'] += 1
            log.debug(f"DNS resolve exhausted all upstreams: {e}")
            return None
        except Exception as e:
            self._stats['resolve_errors'] += 1
            log.debug(f"DNS resolve error: {e}")
            return None

    async def _forward(self, query: bytes, client_xid: int) -> Optional[bytes]:
        """Forward one query to upstream via the pool. Returns response bytes
        with client_xid preserved. Propagates UpstreamExhausted so resolve()
        can count it as a resolve_error; followers in singleflight are told
        via the failed Future and convert it to None themselves."""
        return await self._pool.query(query, client_xid)

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

    def _extract_qtype_qclass(self, query: bytes) -> Tuple[int, int]:
        """Extract (qtype, qclass) from DNS query. Returns (0, 0) on parse error.

        qtype: A=1, AAAA=28, MX=15, TXT=16, etc. (RFC 1035 §3.2.2)
        qclass: IN=1, CH=3, HS=4 (RFC 1035 §3.2.4). Almost always IN on the
        public internet, but keyed here so we never collapse IN/CH queries.
        """
        try:
            # Skip header (12 bytes) and find end of domain name
            pos = 12
            while pos < len(query) and query[pos] != 0:
                length = query[pos]
                if length >= 64:  # Compression pointer (not valid in question, defensive)
                    pos += 2
                    break
                pos += 1 + length
            else:
                pos += 1  # Skip null terminator

            # QTYPE + QCLASS are 4 bytes after the domain name
            if pos + 4 <= len(query):
                qtype, qclass = struct.unpack('!HH', query[pos:pos + 4])
                return qtype, qclass
            return 0, 0
        except Exception:
            return 0, 0

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

    def get_stats(self) -> dict:
        """Get DNS server statistics, including counters and upstream pool state."""
        return {
            "enabled": getattr(self.config, 'dot_enabled', True),
            "upstream": getattr(self.config, 'dot_upstream', 'cloudflare'),
            "upstream_ip": self.upstream_ip,
            "upstream_port": self.upstream_port,
            "upstreams": self._pool.upstream_info(),
            "blocked_domains": len(self.blocked_domains),
            "cache_enabled": self._cache_enabled,
            "cache_size": len(self._cache),
            "in_flight": len(self._in_flight),
            "last_blocklist_update": self._last_blocklist_update,
            "counters": dict(self._stats),
        }
