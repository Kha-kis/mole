"""
MOLE PIA Provider - Private Internet Access VPN integration
"""

import base64
import concurrent.futures
import json
import re
import socket
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from ..config import Config
from ..constants import DEFAULT_CONFIG_FILE
from ..utils import (
    VPNProvider,
    VPNState,
    log,
    run_cmd,
    run_in_netns,
    sanitize_for_log,
    secure_write_file,
)


def apply_region_to_config(region: str, server: str = None) -> bool:
    """Apply region (and optionally server) selection to config file"""

    try:
        with open(DEFAULT_CONFIG_FILE, 'r') as f:
            config_content = f.read()

        # Update or add PIA_REGION
        if re.search(r'^PIA_REGION=', config_content, re.MULTILINE):
            config_content = re.sub(
                r'^PIA_REGION=.*$',
                f'PIA_REGION={region}',
                config_content,
                flags=re.MULTILINE
            )
        else:
            if not config_content.endswith('\n'):
                config_content += '\n'
            config_content += f'\nPIA_REGION={region}\n'

        # Update or add/remove PIA_SERVER
        if server:
            if re.search(r'^PIA_SERVER=', config_content, re.MULTILINE):
                config_content = re.sub(
                    r'^PIA_SERVER=.*$',
                    f'PIA_SERVER={server}',
                    config_content,
                    flags=re.MULTILINE
                )
            elif re.search(r'^#\s*PIA_SERVER=', config_content, re.MULTILINE):
                # Uncomment and set
                config_content = re.sub(
                    r'^#\s*PIA_SERVER=.*$',
                    f'PIA_SERVER={server}',
                    config_content,
                    flags=re.MULTILINE
                )
            else:
                # Add after PIA_REGION
                config_content = re.sub(
                    r'^(PIA_REGION=.*)$',
                    f'\\1\nPIA_SERVER={server}',
                    config_content,
                    flags=re.MULTILINE
                )
        else:
            # Comment out PIA_SERVER if it exists (region-only selection)
            if re.search(r'^PIA_SERVER=', config_content, re.MULTILINE):
                config_content = re.sub(
                    r'^PIA_SERVER=(.*)$',
                    r'# PIA_SERVER=\1',
                    config_content,
                    flags=re.MULTILINE
                )

        with open(DEFAULT_CONFIG_FILE, 'w') as f:
            f.write(config_content)

        if server:
            print(f"\nConfig updated:")
            print(f"  PIA_REGION={region}")
            print(f"  PIA_SERVER={server}")
        else:
            print(f"\nConfig updated: PIA_REGION={region}")

        print("Restart MOLE for changes to take effect: sudo systemctl restart mole")
        return True

    except PermissionError:
        print(f"\nError: Permission denied writing to {DEFAULT_CONFIG_FILE}")
        print("Run with sudo to update config, or add manually:")
        print(f"  PIA_REGION={region}")
        if server:
            print(f"  PIA_SERVER={server}")
        return False
    except Exception as e:
        print(f"\nError updating config: {e}")
        return False


class PIAProvider(VPNProvider):
    """Private Internet Access VPN provider"""

    @property
    def name(self) -> str:
        return "PIA"

    @property
    def _user(self) -> str:
        return self.config.get('PIA_USER', '')

    @property
    def _pass(self) -> str:
        return self.config.get('PIA_PASS', '')

    @property
    def _regions(self) -> List[str]:
        """Get list of regions (supports comma-separated fallback)"""
        region_str = self.config.get('PIA_REGION', '')
        if not region_str:
            return []
        return [r.strip() for r in region_str.split(',') if r.strip()]

    @property
    def _server_hostname(self) -> Optional[str]:
        """Get specific server hostname if configured"""
        hostname = self.config.get('PIA_SERVER', '').strip()
        return hostname if hostname else None

    @property
    def _dip_token(self) -> Optional[str]:
        """Get Dedicated IP token if configured"""
        token = self.config.get('PIA_DIP_TOKEN', '').strip()
        return token if token else None

    @property
    def _max_latency(self) -> int:
        """Get maximum latency threshold for server selection (ms)"""
        try:
            return int(self.config.get('PIA_MAX_LATENCY', '0'))
        except (ValueError, TypeError):
            return 0

    @property
    def _prefer_last_server(self) -> bool:
        """Whether to prefer reconnecting to the last used server"""
        val = self.config.get('PIA_PREFER_LAST_SERVER', 'true').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def _saved_server(self) -> Optional[str]:
        """Get the last used server hostname from state"""
        try:
            hostname_file = Path(self.config.state_dir) / "hostname"
            if hostname_file.exists():
                return hostname_file.read_text().strip()
        except Exception:
            pass
        return None

    @property
    def _ca_cert(self) -> str:
        return f"{self.config.config_dir}/providers/pia-ca.crt"

    async def _autodetect_region(self) -> Optional[str]:
        """Auto-detect the best region based on latency and save to config"""

        try:
            # Fetch regions
            with urllib.request.urlopen(
                "https://serverlist.piaservers.net/vpninfo/servers/v6",
                timeout=30
            ) as resp:
                data = resp.readline().decode()
                servers = json.loads(data)

            # Filter to port forwarding regions if needed
            pf_only = self.config.port_forward
            regions = []
            for region in servers.get("regions", []):
                if pf_only and not region.get("port_forward"):
                    continue
                wg_servers = region.get("servers", {}).get("wg", [])
                if wg_servers:
                    regions.append({
                        "id": region["id"],
                        "name": region["name"],
                        "ip": wg_servers[0]["ip"]
                    })

            if not regions:
                log.error("No suitable regions found")
                return None

            log.info(f"Testing {len(regions)} regions...")

            # Ping test regions in parallel
            def ping_region(r):
                try:
                    result = run_cmd(["ping", "-c", "1", "-W", "2", r["ip"]], check=False)
                    if result.returncode == 0:
                        for part in result.stdout.split():
                            if part.startswith("time="):
                                return (r, float(part[5:]))
                except Exception:
                    pass
                return (r, None)

            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(ping_region, r) for r in regions]
                for future in concurrent.futures.as_completed(futures):
                    region, latency = future.result()
                    if latency is not None:
                        results.append((region, latency))

            if not results:
                log.error("Could not reach any regions")
                return None

            # Filter by MAX_LATENCY threshold if set
            max_latency = self._max_latency
            if max_latency > 0:
                filtered = [(r, l) for r, l in results if l <= max_latency]
                if filtered:
                    log.info(f"Filtered to {len(filtered)} regions under {max_latency}ms latency")
                    results = filtered
                else:
                    log.warning(f"No regions under {max_latency}ms, using all {len(results)} results")

            # Sort by latency and pick best
            results.sort(key=lambda x: x[1])
            best = results[0][0]
            best_latency = results[0][1]

            log.info(f"Best region: {best['name']} ({best['id']}) - {best_latency:.1f} ms")

            # Save to config
            apply_region_to_config(best['id'])

            return best['id']

        except Exception as e:
            log.error(f"Auto-detect failed: {e}")
            return None

    async def authenticate(self) -> bool:
        """Get PIA authentication token with exponential backoff for rate limits."""
        log.info("Authenticating with PIA...")

        max_retries = 3
        base_delay = 30  # PIA rate limits are stricter, start with 30 seconds

        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    delay = base_delay * (2 ** (attempt - 1))  # 30, 60, 120 seconds
                    log.info(f"Retry attempt {attempt}/{max_retries} in {delay}s...")
                    time.sleep(delay)

                result = run_cmd([
                    "curl", "-s", "--location", "--request", "POST",
                    "https://www.privateinternetaccess.com/api/client/v2/token",
                    "--form", f"username={self._user}",
                    "--form", f"password={self._pass}"
                ], check=False)

                if result.returncode == 0 and result.stdout:
                    data = json.loads(result.stdout)

                    if "token" in data:
                        self.state.token = data["token"]
                        self.state.token_expires = datetime.now() + timedelta(hours=24)
                        log.info("Authentication successful")
                        return True

                    # Check for rate limit response
                    if data.get("status") == "error":
                        error_code = data.get("code", "")
                        if "too_many" in error_code.lower():
                            if attempt < max_retries:
                                log.warning(f"Rate limited by PIA, will retry with backoff")
                                continue
                            else:
                                log.error(f"Rate limited after {max_retries} retries. Wait 15+ minutes before trying again.")
                                return False

                log.error(f"Authentication failed: {sanitize_for_log(result.stderr or result.stdout)}")
                return False

            except Exception as e:
                log.error(f"Authentication error: {sanitize_for_log(str(e))}")
                return False

        return False

    async def _get_dedicated_ip(self) -> bool:
        """Get Dedicated IP server info using DIP token.

        Returns True if dedicated IP was successfully retrieved.
        """
        log.info("Using Dedicated IP token...")

        try:
            # Build request
            url = "https://www.privateinternetaccess.com/api/client/v2/dedicated_ip"
            data = json.dumps({"tokens": [self._dip_token]}).encode('utf-8')

            req = urllib.request.Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')
            req.add_header('Authorization', f'Token {self.state.token}')

            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())

            # Result is an array of dedicated IPs
            if not result or not isinstance(result, list) or len(result) == 0:
                log.error("No dedicated IP returned from API")
                return False

            dip_info = result[0]

            # Check status
            if dip_info.get('status') != 'active':
                log.error(f"Dedicated IP status: {dip_info.get('status', 'unknown')}")
                return False

            # Extract server info
            self.state.server_ip = dip_info.get('ip')
            self.state.server_hostname = dip_info.get('cn')

            if not self.state.server_ip or not self.state.server_hostname:
                log.error("Dedicated IP response missing ip or hostname")
                return False

            # Log expiration if available
            dip_expire = dip_info.get('dip_expire')
            if dip_expire:
                log.info(f"Dedicated IP: {self.state.server_hostname} ({self.state.server_ip})")
                log.info(f"Dedicated IP expires: {dip_expire}")
            else:
                log.info(f"Dedicated IP: {self.state.server_hostname} ({self.state.server_ip})")

            return True

        except urllib.error.HTTPError as e:
            log.error(f"Dedicated IP API error: {e.code} {e.reason}")
            return False
        except Exception as e:
            log.error(f"Dedicated IP error: {sanitize_for_log(str(e))}")
            return False

    async def get_server(self) -> bool:
        """Get PIA server with fallback regions and optional specific server.

        Server selection priority:
        1. Dedicated IP (if PIA_DIP_TOKEN set)
        2. Specific server (if PIA_SERVER set)
        3. Last used server (if PIA_PREFER_LAST_SERVER=true, default)
        4. First available server in region
        """
        # Check for Dedicated IP first
        if self._dip_token:
            if await self._get_dedicated_ip():
                return True
            log.warning("Dedicated IP failed, falling back to normal server selection...")

        regions_to_try = self._regions
        target_hostname = self._server_hostname
        using_saved_server = False

        # Check if user requested a new server (via touch file)
        new_server_file = Path(self.config.state_dir) / "new-server"
        force_new_server = new_server_file.exists()
        if force_new_server:
            log.info("New server requested, will select fresh server")
            new_server_file.unlink()  # Remove the flag file

        # If no explicit server set, try to reconnect to last used server
        if not target_hostname and self._prefer_last_server and not force_new_server:
            saved = self._saved_server
            if saved:
                log.info(f"Trying to reconnect to last server: {saved}")
                target_hostname = saved
                using_saved_server = True

        if not regions_to_try:
            log.info("PIA_REGION not set - auto-detecting best region...")
            best_region = await self._autodetect_region()
            if not best_region:
                log.error("Could not auto-detect region")
                return False
            regions_to_try = [best_region]

        if target_hostname:
            log.info(f"Looking for server: {target_hostname} in regions: {', '.join(regions_to_try)}")
        else:
            log.info(f"Getting server for regions: {', '.join(regions_to_try)}")

        try:
            with urllib.request.urlopen(
                "https://serverlist.piaservers.net/vpninfo/servers/v6",
                timeout=30
            ) as resp:
                data = resp.readline().decode()
                servers = json.loads(data)

            # Try each region in order (fallback support)
            for region_id in regions_to_try:
                for region in servers.get("regions", []):
                    if region["id"] == region_id:
                        wg_servers = region.get("servers", {}).get("wg", [])

                        if target_hostname:
                            # Find specific server by hostname
                            for server in wg_servers:
                                if server["cn"] == target_hostname:
                                    self.state.server_ip = server["ip"]
                                    self.state.server_hostname = server["cn"]
                                    log.info(f"Server: {self.state.server_hostname} ({self.state.server_ip})")
                                    return True
                            log.warning(f"Server '{target_hostname}' not found in region '{region_id}'")
                        elif wg_servers:
                            # Use first available server in region
                            server = wg_servers[0]
                            self.state.server_ip = server["ip"]
                            self.state.server_hostname = server["cn"]
                            log.info(f"Server: {self.state.server_hostname} ({self.state.server_ip})")
                            return True
                        else:
                            log.warning(f"No WireGuard servers in region '{region_id}'")
                        break
                else:
                    log.warning(f"Region '{region_id}' not found, trying next...")
                    continue

            # If we tried a saved server and it wasn't found, fall back to any available
            if using_saved_server and target_hostname:
                log.info(f"Last server '{target_hostname}' unavailable, selecting new server...")
                for region_id in regions_to_try:
                    for region in servers.get("regions", []):
                        if region["id"] == region_id:
                            wg_servers = region.get("servers", {}).get("wg", [])
                            if wg_servers:
                                server = wg_servers[0]
                                self.state.server_ip = server["ip"]
                                self.state.server_hostname = server["cn"]
                                log.info(f"Server: {self.state.server_hostname} ({self.state.server_ip})")
                                return True
                            break

            log.error("All regions exhausted, no suitable server found")
        except Exception as e:
            log.error(f"Failed to get server: {e}")

        return False

    async def register_wireguard(self) -> bool:
        """Register WireGuard with PIA"""
        import subprocess
        log.info("Registering WireGuard...")

        try:
            # Generate keys
            result = run_cmd(["wg", "genkey"])
            priv_key = result.stdout.strip()

            proc = subprocess.run(["wg", "pubkey"], input=priv_key, capture_output=True, text=True)
            pub_key = proc.stdout.strip()

            # Register with PIA API
            ctx = ssl.create_default_context()
            ctx.load_verify_locations(self._ca_cert)

            params = urllib.parse.urlencode({"pt": self.state.token, "pubkey": pub_key})
            url = f"https://{self.state.server_hostname}:1337/addKey?{params}"

            req = urllib.request.Request(url)
            req.add_header("Host", self.state.server_hostname)

            # Patch socket to connect to correct IP
            orig_create_connection = socket.create_connection
            def patched_create_connection(address, *args, **kwargs):
                host, port = address
                if host == self.state.server_hostname:
                    return orig_create_connection((self.state.server_ip, port), *args, **kwargs)
                return orig_create_connection(address, *args, **kwargs)

            socket.create_connection = patched_create_connection
            try:
                with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                    result = json.loads(resp.read().decode())
            finally:
                socket.create_connection = orig_create_connection

            if result.get("status") == "OK":
                self.state.peer_ip = result["peer_ip"]
                self.state.server_vip = result["server_vip"]

                # Use DOT server if enabled, otherwise use PIA's DNS
                if self.config.dot_enabled:
                    dns_server = self.config.dot_bind
                else:
                    dns_server = result['dns_servers'][0]

                # Write WireGuard config.
                # DNS line is opt-in: when running in a netns with a
                # bind-mounted /etc/resolv.conf, wg-quick's resolvconf hook
                # fails on mv. See Config.wg_dns_in_conf.
                interface_lines = [
                    "[Interface]",
                    f"PrivateKey = {priv_key}",
                    f"Address = {result['peer_ip']}/32",
                ]
                if self.config.wg_dns_in_conf:
                    interface_lines.append(f"DNS = {dns_server}")
                wg_config = "\n".join(interface_lines) + "\n\n" + (
                    f"[Peer]\n"
                    f"PublicKey = {result['server_key']}\n"
                    f"Endpoint = {self.state.server_ip}:{result['server_port']}\n"
                    f"AllowedIPs = 0.0.0.0/0\n"
                    f"PersistentKeepalive = 25\n"
                )
                # Write WireGuard config with restricted permissions (contains private key)
                secure_write_file(Path(self.config.wg_conf), wg_config)

                # Save state (with restricted permissions)
                state_dir = Path(self.config.state_dir)
                state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                secure_write_file(state_dir / "server_ip", self.state.server_ip)
                secure_write_file(state_dir / "hostname", self.state.server_hostname)
                secure_write_file(state_dir / "server_vip", self.state.server_vip)

                log.info(f"WireGuard registered, peer IP: {self.state.peer_ip}")
                return True
            else:
                log.error(f"WireGuard registration failed: {result}")
        except Exception as e:
            log.error(f"WireGuard registration error: {e}")

        return False

    def _load_saved_port_forward(self) -> bool:
        """Try to load saved port forwarding state from disk.

        Returns True if valid saved state was loaded, False otherwise.
        The saved state is valid if:
        - pf-response.json exists
        - The payload hasn't expired (with 1 day safety margin)

        Note: PIA allows binding ports on any server, so we try to reuse
        the saved signature even if the server changed. If binding fails,
        setup_port_forward() will request a new signature.
        """
        state_dir = Path(self.config.state_dir)
        pf_file = state_dir / "pf-response.json"

        if not pf_file.exists():
            log.debug("No saved port forwarding state found")
            return False

        try:
            pf_response = json.loads(pf_file.read_text())

            if pf_response.get("status") != "OK":
                log.debug("Saved port forward state is invalid")
                return False

            payload = pf_response.get("payload")
            signature = pf_response.get("signature")

            if not payload or not signature:
                log.debug("Saved port forward state missing payload/signature")
                return False

            # Decode and check expiration
            port_data = json.loads(base64.b64decode(payload))
            expires_at = datetime.fromisoformat(
                port_data["expires_at"].replace("Z", "+00:00")
            )

            # Check if expired (with 1 day safety margin)
            now = datetime.now(expires_at.tzinfo)
            if expires_at <= now + timedelta(days=1):
                days_left = (expires_at - now).days
                log.info(f"Saved port forward expires in {days_left} days, getting new one")
                return False

            # Check if server changed (informational only - PIA allows cross-server binding)
            saved_server = pf_response.get("server_hostname")
            if saved_server and saved_server != self.state.server_hostname:
                log.info(f"Server changed ({saved_server} -> {self.state.server_hostname}), will try to rebind saved port")

            # Load into state
            self.state.port_payload = payload
            self.state.port_signature = signature
            self.state.port = port_data["port"]
            self.state.port_expires = expires_at

            days_remaining = (expires_at - now).days
            log.info(f"Loaded saved port {self.state.port} (expires in {days_remaining} days)")
            return True

        except Exception as e:
            log.warning(f"Failed to load saved port forward state: {e}")
            return False

    async def setup_port_forward(self) -> bool:
        """Setup PIA port forwarding.

        First tries to reuse saved port forwarding state (valid for ~60 days).
        Only requests a new port if no valid saved state exists.
        """
        log.info("Setting up port forwarding...")

        # Try to reuse saved port forwarding state
        if self._load_saved_port_forward():
            log.info("Reusing saved port forward, binding...")
            if await self.refresh_port_forward():
                log.info(f"Port {self.state.port} bound successfully (reused)")
                return True
            else:
                log.warning("Failed to bind saved port, requesting new one...")

        # Request new port forwarding signature
        log.info("Requesting new port forward signature...")
        try:
            result = run_in_netns([
                "curl", "-s", "-m", "15",
                "--resolve", f"{self.state.server_hostname}:19999:{self.state.server_vip}",
                "--cacert", self._ca_cert,
                f"https://{self.state.server_hostname}:19999/getSignature?token={self.state.token}"
            ], self.config.netns)

            pf_response = json.loads(result.stdout)

            if pf_response.get("status") != "OK":
                log.error(f"Port forward request failed: {sanitize_for_log(str(pf_response))}")
                return False

            self.state.port_payload = pf_response["payload"]
            self.state.port_signature = pf_response["signature"]

            # Decode port info
            port_data = json.loads(base64.b64decode(self.state.port_payload))
            self.state.port = port_data["port"]
            self.state.port_expires = datetime.fromisoformat(
                port_data["expires_at"].replace("Z", "+00:00")
            )

            # Save state (with restricted permissions for sensitive data)
            # Include server_hostname for tracking across restarts
            state_dir = Path(self.config.state_dir)
            pf_response["server_hostname"] = self.state.server_hostname
            secure_write_file(state_dir / "pf-response.json", json.dumps(pf_response))
            secure_write_file(state_dir / "port", str(self.state.port))

            log.info(f"New port {self.state.port} assigned (expires: {self.state.port_expires})")

            return await self.refresh_port_forward()

        except Exception as e:
            log.error(f"Port forward setup error: {e}")
            return False

    async def refresh_port_forward(self) -> bool:
        """Refresh PIA port forwarding"""
        try:
            result = run_in_netns([
                "curl", "-Gs", "-m", "15",
                "--connect-to", f"{self.state.server_hostname}::{self.state.server_vip}:",
                "--cacert", self._ca_cert,
                "--data-urlencode", f"payload={self.state.port_payload}",
                "--data-urlencode", f"signature={self.state.port_signature}",
                f"https://{self.state.server_hostname}:19999/bindPort"
            ], self.config.netns)

            response = json.loads(result.stdout)

            if response.get("status") == "OK":
                return True
            else:
                log.warning(f"Port refresh failed: {sanitize_for_log(str(response))}")
                return False
        except Exception as e:
            log.error(f"Port refresh error: {sanitize_for_log(str(e))}")
            return False
