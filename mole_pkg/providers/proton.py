"""
MOLE Proton Provider - ProtonVPN integration

Uses proton.Session with TLS pinning disabled for compatibility.
Port forwarding uses NAT-PMP protocol.
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from proton import Session as ProtonAPISession

from ..config import Config
from ..utils import (
    VPNProvider,
    VPNState,
    log,
    run_cmd,
    run_in_netns,
    sanitize_for_log,
    secure_write_file,
)

# Proton API configuration
PROTON_API_URL = "https://account.protonvpn.com/api"
PROTON_APP_VERSION = "LinuxVPN_4.4.2"


class ProtonSessionWrapper:
    """Wrapper around proton.Session with persistence support"""

    def __init__(self, session_file: Path):
        self.session_file = session_file
        self._session: Optional[ProtonAPISession] = None

    def _create_session(self) -> ProtonAPISession:
        """Create a new Proton API session"""
        return ProtonAPISession(
            api_url=PROTON_API_URL,
            appversion=PROTON_APP_VERSION,
            user_agent="ProtonVPN/4.4.2 (Linux; Ubuntu 22.04)",
            TLSPinning=False,  # Disable to avoid urllib3 compatibility issues
            timeout=30
        )

    def load(self) -> bool:
        """Load session from disk"""
        try:
            if self.session_file.exists():
                dump = self.session_file.read_text()
                self._session = ProtonAPISession.load(
                    dump,
                    TLSPinning=False,
                    timeout=30
                )
                log.debug("Loaded saved Proton session")
                return True
        except Exception as e:
            log.debug(f"Could not load session: {e}")
        return False

    def save(self) -> None:
        """Save session to disk"""
        if not self._session:
            return
        try:
            dump = self._session.dump()
            # dump() returns a dict, convert to JSON string
            if isinstance(dump, dict):
                dump = json.dumps(dump)
            secure_write_file(self.session_file, dump)
            log.debug("Saved Proton session")
        except Exception as e:
            log.warning(f"Could not save session: {e}")

    def refresh(self) -> bool:
        """Refresh access token"""
        if not self._session:
            return False

        try:
            log.info("Refreshing session...")
            self._session.refresh()
            self.save()
            log.info("Session refreshed successfully")
            return True
        except Exception as e:
            log.warning(f"Session refresh failed: {e}")
            return False

    def authenticate(self, username: str, password: str, max_retries: int = 3) -> bool:
        """Authenticate with Proton using exponential backoff for rate limits.

        Args:
            username: Proton account username
            password: Proton account password
            max_retries: Maximum number of retry attempts (default 3)
        """
        base_delay = 5  # Start with 5 seconds

        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    delay = base_delay * (2 ** (attempt - 1))  # 5, 10, 20 seconds
                    log.info(f"Retry attempt {attempt}/{max_retries} in {delay}s...")
                    time.sleep(delay)

                log.info("Authenticating (this may take a moment)...")
                self._session = self._create_session()
                scopes = self._session.authenticate(username, password)

                if 'vpn' not in scopes:
                    log.error("Account does not have VPN access")
                    return False

                self.save()
                log.info("Authentication successful")
                return True

            except Exception as e:
                error_str = str(e).lower()
                # Check for rate limit indicators
                if "too many" in error_str or "rate" in error_str or "429" in error_str:
                    if attempt < max_retries:
                        log.warning(f"Rate limited, will retry with backoff")
                        continue
                    else:
                        log.error(f"Rate limited after {max_retries} retries. Wait before trying again.")
                        return False

                log.error(f"Authentication failed: {sanitize_for_log(str(e))}")
                return False

        return False

    def api_request(self, endpoint: str, method: str = "GET", data: dict = None) -> dict:
        """Make API request"""
        if not self._session:
            raise Exception("Not authenticated")
        return self._session.api_request(endpoint, jsondata=data, method=method)


class ProtonProvider(VPNProvider):
    """ProtonVPN provider using official Proton API"""

    def __init__(self, config: Config, state: VPNState):
        super().__init__(config, state)
        self._session_file = Path(self.config.state_dir) / "proton_session.json"
        self._proton_session: Optional[ProtonSessionWrapper] = None
        self._selected_server: Optional[Dict] = None

    @property
    def name(self) -> str:
        return "ProtonVPN"

    @property
    def _user(self) -> str:
        return self.config.get('PROTON_USER', '')

    @property
    def _pass(self) -> str:
        return self.config.get('PROTON_PASS', '')

    @property
    def _tier(self) -> int:
        """User tier: 0=free, 1=basic, 2=plus/visionary"""
        try:
            return int(self.config.get('PROTON_TIER', '2'))
        except ValueError:
            return 2

    @property
    def _server_name(self) -> Optional[str]:
        """Specific server name (e.g., 'US-CA#1')"""
        server = self.config.get('PROTON_SERVER', '').strip()
        return server if server else None

    @property
    def _prefer_p2p(self) -> bool:
        """Prefer P2P-enabled servers (required for port forwarding)"""
        val = self.config.get('PROTON_PREFER_P2P', 'true').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def _natpmp_gateway(self) -> str:
        """NAT-PMP gateway address (usually 10.2.0.1)"""
        return self.config.get('PROTON_NATPMP_GATEWAY', '10.2.0.1')

    @property
    def _countries(self) -> List[str]:
        """Get list of countries (supports comma-separated fallback like PIA)"""
        country_str = self.config.get('PROTON_COUNTRY', '').strip().upper()
        if not country_str:
            return []
        return [c.strip() for c in country_str.split(',') if c.strip()]

    @property
    def _max_latency(self) -> int:
        """Get maximum latency threshold for server selection (ms)"""
        try:
            return int(self.config.get('PROTON_MAX_LATENCY', '0'))
        except (ValueError, TypeError):
            return 0

    @property
    def _prefer_last_server(self) -> bool:
        """Whether to prefer reconnecting to the last used server"""
        val = self.config.get('PROTON_PREFER_LAST_SERVER', 'true').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def _saved_server(self) -> Optional[str]:
        """Get the last used server name from state"""
        try:
            server_file = Path(self.config.state_dir) / "server_name"
            if server_file.exists():
                return server_file.read_text().strip()
        except Exception:
            pass
        return None

    @property
    def _netshield_level(self) -> int:
        """NetShield protection level: 0=off, 1=block malware, 2=block malware+ads+trackers"""
        try:
            level = int(self.config.get('PROTON_NETSHIELD', '0'))
            return max(0, min(2, level))  # Clamp to 0-2
        except (ValueError, TypeError):
            return 0

    async def authenticate(self) -> bool:
        """Authenticate with ProtonVPN"""
        log.info("Authenticating with ProtonVPN...")

        self._proton_session = ProtonSessionWrapper(self._session_file)

        # Try to load and refresh existing session
        if self._proton_session.load():
            if self._proton_session.refresh():
                return True
            log.warning("Session refresh failed, re-authenticating...")

        # Fresh authentication
        if not self._user or not self._pass:
            log.error("PROTON_USER and PROTON_PASS must be set in config")
            return False

        return self._proton_session.authenticate(self._user, self._pass)

    async def _fetch_servers(self) -> Optional[List[Dict]]:
        """Fetch server list from ProtonVPN API"""
        if not self._proton_session:
            log.error("Not authenticated")
            return None

        try:
            log.info("Fetching server list...")
            response = self._proton_session.api_request("/vpn/logicals")

            if response.get("Code") != 1000:
                log.error(f"Failed to fetch servers: {response.get('Error')}")
                return None

            servers = response.get("LogicalServers", [])
            log.info(f"Found {len(servers)} servers")
            return servers

        except Exception as e:
            log.error(f"Failed to fetch servers: {sanitize_for_log(str(e))}")
            return None

    def _filter_servers(self, servers: List[Dict], country: Optional[str] = None) -> List[Dict]:
        """Filter servers based on user preferences.

        Args:
            servers: Raw server list from API
            country: Optional country code to filter by (for fallback support)
        """
        filtered = []

        for server in servers:
            # Skip disabled servers
            if server.get("Status") == 0:
                continue

            # Skip servers above user's tier
            if server.get("Tier", 0) > self._tier:
                continue

            # Filter by country if specified
            if country and server.get("ExitCountry") != country:
                continue

            # Filter for P2P if port forwarding enabled
            if self.config.port_forward or self._prefer_p2p:
                features = server.get("Features", 0)
                if not (features & 4):  # Feature bit 4 = P2P
                    continue

            # Get WireGuard server info
            servers_list = server.get("Servers", [])
            for s in servers_list:
                if s.get("X25519PublicKey"):
                    filtered.append({
                        "name": server.get("Name"),
                        "hostname": server.get("Domain"),
                        "entry_ip": s.get("EntryIP"),
                        "exit_ip": s.get("ExitIP"),
                        "public_key": s.get("X25519PublicKey"),
                        "country": server.get("ExitCountry"),
                        "city": server.get("City"),
                        "load": server.get("Load", 0),
                        "tier": server.get("Tier", 0),
                        "features": server.get("Features", 0),
                        "score": server.get("Score", 0),
                    })
                    break

        return filtered

    def _ping_server(self, server: Dict) -> Optional[float]:
        """Ping a server and return latency in ms, or None if unreachable"""
        try:
            result = run_cmd(
                ["ping", "-c", "1", "-W", "2", server["entry_ip"]],
                check=False
            )
            if result.returncode == 0:
                for part in result.stdout.split():
                    if part.startswith("time="):
                        return float(part[5:])
        except Exception:
            pass
        return None

    def _filter_by_latency(self, servers: List[Dict]) -> List[Dict]:
        """Filter and sort servers by latency if PROTON_MAX_LATENCY is set"""
        import concurrent.futures

        max_latency = self._max_latency
        if max_latency <= 0 and len(servers) <= 5:
            # No latency filtering, just return sorted by load
            return servers

        log.info(f"Testing latency for {min(len(servers), 20)} servers...")

        # Test up to 20 servers in parallel
        test_servers = servers[:20]
        results = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._ping_server, s): s for s in test_servers}
            for future in concurrent.futures.as_completed(futures):
                server = futures[future]
                latency = future.result()
                if latency is not None:
                    results.append((server, latency))

        if not results:
            log.warning("Could not reach any servers, using load-based selection")
            return servers

        # Filter by max latency if set
        if max_latency > 0:
            filtered = [(s, l) for s, l in results if l <= max_latency]
            if filtered:
                log.info(f"Filtered to {len(filtered)} servers under {max_latency}ms")
                results = filtered
            else:
                log.warning(f"No servers under {max_latency}ms, using all {len(results)} reachable")

        # Sort by latency
        results.sort(key=lambda x: x[1])

        # Log best options
        if results:
            best = results[0]
            log.info(f"Best latency: {best[0]['name']} - {best[1]:.1f}ms")

        return [r[0] for r in results]

    async def get_server(self) -> bool:
        """Get ProtonVPN server for connection.

        Server selection priority:
        1. Specific server (if PROTON_SERVER set)
        2. Last used server (if PROTON_PREFER_LAST_SERVER=true, default)
        3. Best server by latency/load in configured countries
        """
        servers = await self._fetch_servers()
        if not servers:
            return False

        target_name = self._server_name
        using_saved_server = False

        # Check if user requested a new server (via touch file)
        new_server_file = Path(self.config.state_dir) / "new-server"
        force_new_server = new_server_file.exists()
        if force_new_server:
            log.info("New server requested, will select fresh server")
            new_server_file.unlink()

        # If no explicit server set, try to reconnect to last used server
        if not target_name and self._prefer_last_server and not force_new_server:
            saved = self._saved_server
            if saved:
                log.info(f"Trying to reconnect to last server: {saved}")
                target_name = saved
                using_saved_server = True

        # Get countries list (supports fallback)
        countries_to_try = self._countries
        if not countries_to_try:
            countries_to_try = [None]  # None means no country filter

        # Try each country in order (fallback support)
        for country in countries_to_try:
            if country:
                log.info(f"Trying country: {country}")

            filtered = self._filter_servers(servers, country)
            if not filtered:
                if country:
                    log.warning(f"No suitable servers in {country}, trying next...")
                continue

            log.info(f"Found {len(filtered)} suitable servers" + (f" in {country}" if country else ""))

            # Check for specific/saved server request
            if target_name:
                for server in filtered:
                    if server["name"] == target_name:
                        self._selected_server = server
                        self.state.server_ip = server["entry_ip"]
                        self.state.server_hostname = server["hostname"]
                        log.info(f"Server: {server['name']} ({server['entry_ip']})")
                        return True

                if using_saved_server:
                    log.info(f"Last server '{target_name}' not available, selecting new server...")
                    target_name = None
                    using_saved_server = False
                else:
                    log.warning(f"Server '{target_name}' not found, selecting best available")
                    target_name = None

            # Apply latency filtering if configured or many servers
            if self._max_latency > 0 or len(filtered) > 5:
                filtered = self._filter_by_latency(filtered)
            else:
                # Sort by load (lower is better)
                filtered.sort(key=lambda s: s["load"])

            if filtered:
                server = filtered[0]
                self._selected_server = server
                self.state.server_ip = server["entry_ip"]
                self.state.server_hostname = server["hostname"]
                log.info(f"Server: {server['name']} ({server['entry_ip']}) - {server['load']}% load")
                return True

        # All countries exhausted
        log.error("No suitable servers found matching criteria")
        if self._countries:
            log.error(f"  Countries tried: {', '.join(self._countries)}")
        if self.config.port_forward:
            log.error("  Port forwarding requires P2P servers (Plus plan)")
        return False

    def _generate_wireguard_keys(self) -> tuple:
        """Generate WireGuard keys via ProtonVPN API

        ProtonVPN requires EC (Ed25519) keys registered via their API.
        The Ed25519 private key is then converted to X25519 for WireGuard.

        Returns:
            tuple: (x25519_private_key, ed25519_public_key) both base64 encoded
        """
        import base64
        import hashlib

        # Step 1: Get EC keys from ProtonVPN API
        log.debug("Requesting EC keys from ProtonVPN...")
        key_response = self._proton_session.api_request("/vpn/v1/certificate/key/EC")

        if key_response.get('Code') != 1000:
            raise Exception(f"Key generation failed: {key_response.get('Error')}")

        private_key_pem = key_response.get('PrivateKey')
        public_key_pem = key_response.get('PublicKey')

        # Step 2: Extract raw Ed25519 seed from PEM (PKCS#8 format)
        private_key_b64 = private_key_pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace("\n", "")
        public_key_b64 = public_key_pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "").replace("\n", "")

        private_key_der = base64.b64decode(private_key_b64)
        public_key_der = base64.b64decode(public_key_b64)

        # Ed25519 seed is the last 32 bytes of the PKCS#8 structure
        ed25519_seed = private_key_der[-32:]

        # Ed25519 public key is the last 32 bytes of the SPKI structure
        ed25519_public = base64.b64encode(public_key_der[-32:]).decode()

        # Step 3: Convert Ed25519 seed to X25519 private key
        # SHA-512 hash of seed, take first 32 bytes, then clamp for X25519
        hash_bytes = hashlib.sha512(ed25519_seed).digest()[:32]

        clamped = bytearray(hash_bytes)
        clamped[0] &= 0xf8   # Clear bottom 3 bits
        clamped[31] &= 0x7f  # Clear top bit
        clamped[31] |= 0x40  # Set second highest bit

        x25519_private_key = base64.b64encode(bytes(clamped)).decode()

        return x25519_private_key, ed25519_public

    def _load_saved_certificate(self) -> Optional[Dict]:
        """Load saved certificate if still valid"""
        cert_file = Path(self.config.state_dir) / "proton_certificate.json"
        try:
            if cert_file.exists():
                data = json.loads(cert_file.read_text())
                expiration = data.get("expiration_time", 0)
                # Check if certificate is still valid (with 1 hour margin)
                if expiration > (datetime.now().timestamp() + 3600):
                    log.debug(f"Found valid saved certificate (expires {datetime.fromtimestamp(expiration)})")
                    return data
                else:
                    log.info("Saved certificate expired, will register new one")
        except Exception as e:
            log.debug(f"Could not load saved certificate: {e}")
        return None

    def _save_certificate(self, x25519_private_key: str, ed25519_public_key: str,
                          expiration_time: int, device_name: str) -> None:
        """Save certificate for reuse"""
        cert_file = Path(self.config.state_dir) / "proton_certificate.json"
        try:
            data = {
                "x25519_private_key": x25519_private_key,
                "ed25519_public_key": ed25519_public_key,
                "expiration_time": expiration_time,
                "device_name": device_name,
                "created_at": datetime.now().isoformat(),
            }
            secure_write_file(cert_file, json.dumps(data, indent=2))
            log.debug(f"Saved certificate '{device_name}' (expires {datetime.fromtimestamp(expiration_time)})")
        except Exception as e:
            log.warning(f"Could not save certificate: {e}")

    async def register_wireguard(self) -> bool:
        """Register WireGuard configuration with ProtonVPN"""
        if not self._proton_session or not self._selected_server:
            log.error("Must authenticate and select server first")
            return False

        server = self._selected_server

        # Try to reuse saved certificate
        saved_cert = self._load_saved_certificate()
        if saved_cert:
            log.info(f"Reusing saved certificate '{saved_cert.get('device_name')}'")
            x25519_private_key = saved_cert["x25519_private_key"]
        else:
            # Generate new certificate
            log.info("Registering new WireGuard certificate...")

            try:
                # Generate WireGuard keys via ProtonVPN API
                x25519_private_key, ed25519_public_key = self._generate_wireguard_keys()

                # Use consistent device name for this installation
                device_name = "mole"

                # Register certificate with Ed25519 public key
                netshield = self._netshield_level
                if netshield > 0:
                    log.info(f"NetShield enabled (level {netshield}: {'block malware' if netshield == 1 else 'block malware+ads+trackers'})")

                cert_request = {
                    "ClientPublicKey": ed25519_public_key,
                    "DeviceName": device_name,
                    "Mode": "persistent",
                    "Features": {
                        "SafeMode": False,
                        "SplitTCP": False,
                        "PortForwarding": self.config.port_forward,
                        "NetShieldLevel": netshield,
                        "RandomNAT": False,
                    }
                }

                response = self._proton_session.api_request(
                    "/vpn/v1/certificate",
                    "POST",
                    cert_request
                )

                if response.get("Code") != 1000:
                    log.error(f"Certificate registration failed: {response.get('Error')}")
                    return False

                # Save certificate for future use
                expiration_time = response.get("ExpirationTime", 0)
                self._save_certificate(x25519_private_key, ed25519_public_key,
                                       expiration_time, device_name)

                log.info(f"New certificate registered (expires {datetime.fromtimestamp(expiration_time)})")

            except Exception as e:
                log.error(f"WireGuard registration error: {sanitize_for_log(str(e))}")
                return False

        # Configure WireGuard with the certificate
        try:
            # Proton assigns addresses in 10.2.0.0/16 range
            peer_ip = "10.2.0.2"
            self.state.peer_ip = peer_ip
            self.state.server_vip = server["entry_ip"]

            # DNS server - use our DOT server if enabled, otherwise Proton's
            if self.config.dot_enabled:
                dns_server = self.config.dot_bind
            else:
                dns_server = self._natpmp_gateway  # 10.2.0.1 is also DNS

            # Write WireGuard config with X25519 private key.
            # DNS line is opt-in: when running in a netns with a bind-mounted
            # /etc/resolv.conf, wg-quick's resolvconf hook fails on mv. See
            # Config.wg_dns_in_conf.
            interface_lines = [
                "[Interface]",
                f"PrivateKey = {x25519_private_key}",
                f"Address = {peer_ip}/32",
            ]
            if self.config.wg_dns_in_conf:
                interface_lines.append(f"DNS = {dns_server}")
            wg_config = "\n".join(interface_lines) + "\n\n" + (
                f"[Peer]\n"
                f"PublicKey = {server['public_key']}\n"
                f"Endpoint = {server['entry_ip']}:51820\n"
                f"AllowedIPs = 0.0.0.0/0\n"
                f"PersistentKeepalive = 25\n"
            )
            # Write WireGuard config with restricted permissions (contains private key)
            secure_write_file(Path(self.config.wg_conf), wg_config)

            # Save state
            state_dir = Path(self.config.state_dir)
            state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            secure_write_file(state_dir / "server_ip", self.state.server_ip)
            secure_write_file(state_dir / "hostname", self.state.server_hostname)
            secure_write_file(state_dir / "server_name", server["name"])

            log.info(f"WireGuard configured, peer IP: {peer_ip}")
            return True

        except Exception as e:
            log.error(f"WireGuard config error: {sanitize_for_log(str(e))}")
            return False

    def _load_saved_port(self) -> Optional[int]:
        """Load saved port from state if available"""
        try:
            port_file = Path(self.config.state_dir) / "port"
            if port_file.exists():
                return int(port_file.read_text().strip())
        except Exception:
            pass
        return None

    async def setup_port_forward(self) -> bool:
        """Setup port forwarding using NAT-PMP.

        NAT-PMP assigns ports dynamically, but we track the last assigned port
        to help users identify if their port changed after a reconnection.
        """
        if not self.config.port_forward:
            log.info("Port forwarding disabled")
            return True

        log.info("Setting up port forwarding via NAT-PMP...")

        # Check if natpmpc is installed
        result = run_cmd(["which", "natpmpc"], check=False)
        if result.returncode != 0:
            log.error("natpmpc not installed. Install with: apt install natpmpc")
            return False

        # Load previous port for comparison
        previous_port = self._load_saved_port()

        try:
            gateway = self._natpmp_gateway

            # Request UDP port
            result = run_in_netns([
                "natpmpc", "-a", "1", "0", "udp", "60", "-g", gateway
            ], self.config.netns, check=False)

            if result.returncode != 0:
                log.error(f"NAT-PMP UDP request failed: {result.stderr}")
                return False

            # Parse port from output
            port = None
            for line in result.stdout.split('\n'):
                if "Mapped public port" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "port" and i + 1 < len(parts):
                            try:
                                port = int(parts[i + 1])
                                break
                            except ValueError:
                                continue

            if not port:
                log.error("Could not parse port from NAT-PMP response")
                log.debug(f"NAT-PMP output: {result.stdout}")
                return False

            # Request TCP port (same port)
            result = run_in_netns([
                "natpmpc", "-a", "1", "0", "tcp", "60", "-g", gateway
            ], self.config.netns, check=False)

            if result.returncode != 0:
                log.warning(f"NAT-PMP TCP request failed (UDP port still valid)")

            self.state.port = port
            self.state.port_expires = datetime.now() + timedelta(seconds=60)

            # Save port to state
            state_dir = Path(self.config.state_dir)
            secure_write_file(state_dir / "port", str(port))

            # Notify user if port changed
            if previous_port and previous_port != port:
                log.warning(f"Port changed: {previous_port} -> {port} (update your applications)")
            else:
                log.info(f"Port {port} forwarded via NAT-PMP")

            return True

        except Exception as e:
            log.error(f"Port forwarding error: {sanitize_for_log(str(e))}")
            return False

    async def refresh_port_forward(self) -> bool:
        """Refresh NAT-PMP port mapping (must be called every ~45 seconds)"""
        if not self.config.port_forward or not self.state.port:
            return True

        try:
            gateway = self._natpmp_gateway

            # Refresh UDP mapping
            result = run_in_netns([
                "natpmpc", "-a", "1", "0", "udp", "60", "-g", gateway
            ], self.config.netns, check=False)

            if result.returncode != 0:
                log.warning(f"NAT-PMP UDP refresh failed")
                return False

            # Refresh TCP mapping
            run_in_netns([
                "natpmpc", "-a", "1", "0", "tcp", "60", "-g", gateway
            ], self.config.netns, check=False)

            self.state.port_expires = datetime.now() + timedelta(seconds=60)
            return True

        except Exception as e:
            log.error(f"Port refresh error: {sanitize_for_log(str(e))}")
            return False
