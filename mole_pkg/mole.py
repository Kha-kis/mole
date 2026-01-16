"""
MOLE - Main Orchestrator

Manages VPN connection and spawns services in the VPN namespace.
"""

import asyncio
import os
import signal
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List

from . import __version__
from .config import Config
from .constants import DEFAULT_CONFIG_FILE
from .network import setup_namespace, disconnect_vpn, allow_vpn_server_ip
from .providers import PIAProvider, ProtonProvider
from .services import QBittorrentClient
from .utils import VPNState, VPNProvider, log, run_cmd, run_in_netns, sanitize_for_log, secure_write_file


def get_vpn_provider(config: Config, state: VPNState) -> VPNProvider:
    """Factory function to get VPN provider"""
    providers = {
        "pia": PIAProvider,
        "proton": ProtonProvider,
        "protonvpn": ProtonProvider,
    }

    provider_name = config.vpn_provider.lower()
    if provider_name not in providers:
        raise ValueError(f"Unknown VPN provider: {provider_name}. Supported: {', '.join(providers.keys())}")

    return providers[provider_name](config, state)


def get_torrent_client(config: Config) -> Optional[QBittorrentClient]:
    """Factory function to get torrent client, or None if disabled"""
    client_name = config.torrent_client.lower()

    if client_name in ('none', 'disabled', ''):
        return None

    clients = {
        "qbittorrent": QBittorrentClient,
    }

    if client_name not in clients:
        raise ValueError(f"Unknown torrent client: {client_name}")

    return clients[client_name](config)


class Mole:
    """MOLE - Managed Obfuscated Link Environment"""

    def __init__(self, config_path: str = DEFAULT_CONFIG_FILE):
        self.config_path = config_path
        self.config = Config(config_path)
        self.state = VPNState()
        self.provider = get_vpn_provider(self.config, self.state)
        self.torrent = get_torrent_client(self.config)
        self.shutdown_event = asyncio.Event()
        self._keepalive_task = None
        self._watchdog_task = None
        self._restart_watcher_task = None

        # Subprocess handles for services running in namespace
        self._dns_proc: Optional[subprocess.Popen] = None
        self._proxy_proc: Optional[subprocess.Popen] = None
        self._api_proc: Optional[subprocess.Popen] = None

    async def run(self):
        """Main entry point"""
        log.info("=" * 60)
        log.info(f"MOLE v{__version__} - Managed Obfuscated Link Environment")
        log.info(f"Provider: {self.provider.name}")
        log.info(f"Port forwarding: {'enabled' if self.config.port_forward else 'disabled'}")
        log.info(f"Torrent client: {self.config.torrent_client if self.torrent else 'none'}")
        log.info("=" * 60)

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self._signal_handler)

        # Ensure state directory exists
        state_dir = Path(self.config.state_dir)
        state_dir.mkdir(parents=True, exist_ok=True)

        # Clean up any stale restart trigger
        restart_trigger = state_dir / 'restart_trigger'
        if restart_trigger.exists():
            restart_trigger.unlink()

        # Setup network namespace
        setup_namespace(self.config)

        # Start DNS server in namespace if enabled (must start BEFORE VPN connects)
        if self.config.dot_enabled:
            self._start_dns_server()
            await asyncio.sleep(0.5)

        # Initial VPN setup
        if not await self._full_renewal():
            log.error("Initial setup failed, will retry...")

        # Start background tasks
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())
        self._watchdog_task = asyncio.create_task(self._watchdog_loop())
        self._restart_watcher_task = asyncio.create_task(self._restart_watcher_loop())

        # Start HTTP API server in namespace if enabled
        if self.config.http_api_enabled:
            self._start_api_server()

        # Start HTTP Proxy server in namespace if enabled
        if self.config.proxy_enabled:
            self._start_proxy_server()

        # Main renewal loop
        while not self.shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self.shutdown_event.wait(),
                    timeout=self.config.renewal_interval
                )
            except asyncio.TimeoutError:
                log.info("Scheduled renewal starting...")
                await self._full_renewal()

        log.info("Shutting down...")
        await self._cleanup()

    def _signal_handler(self):
        log.info("Received shutdown signal")
        self.shutdown_event.set()

    def _get_subprocess_env(self) -> dict:
        """Get environment for subprocess with PYTHONPATH set"""
        env = os.environ.copy()
        env["PYTHONPATH"] = "/usr/local/lib/mole"
        return env

    def _start_dns_server(self):
        """Start DNS server as subprocess in namespace"""
        log.info("Starting DNS server in namespace...")

        cmd = [
            "ip", "netns", "exec", self.config.netns,
            sys.executable, "-m", "mole_pkg.services.dns_main",
            "--bind", self.config.dot_bind,
            "--port", str(self.config.dot_port),
            "--upstream", self.config.dot_upstream,
            "--state-dir", self.config.state_dir,
        ]

        if self.config.dot_custom_server:
            cmd.extend(["--custom-server", self.config.dot_custom_server])
        if self.config.dot_block_ads:
            cmd.append("--block-ads")
        if self.config.dot_block_malware:
            cmd.append("--block-malware")
        if self.config.dot_block_tracking:
            cmd.append("--block-tracking")
        if not self.config.dot_caching:
            cmd.append("--no-caching")
        if self.config.dot_cache_ttl:
            cmd.extend(["--cache-ttl", str(self.config.dot_cache_ttl)])

        self._dns_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._get_subprocess_env(),
        )
        log.info(f"DNS server started (PID: {self._dns_proc.pid})")

    def _start_api_server(self):
        """Start API server as subprocess in namespace"""
        log.info("Starting API server in namespace...")

        bind_addr = self.config.http_api_bind
        if not self.config.http_api_key and bind_addr not in ('127.0.0.1', 'localhost', '::1'):
            log.warning("SECURITY WARNING: HTTP API is exposed without authentication!")
            log.warning(f"  Set HTTP_API_KEY in config or bind to 127.0.0.1")

        cmd = [
            "ip", "netns", "exec", self.config.netns,
            sys.executable, "-m", "mole_pkg.services.api_main",
            "--bind", bind_addr,
            "--port", str(self.config.http_api_port),
            "--state-dir", self.config.state_dir,
            "--config", self.config_path,
        ]

        if self.config.http_api_key:
            cmd.extend(["--api-key", self.config.http_api_key])

        self._api_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._get_subprocess_env(),
        )
        log.info(f"API server started on {bind_addr}:{self.config.http_api_port} (PID: {self._api_proc.pid})")

    def _start_proxy_server(self):
        """Start proxy server as subprocess in namespace"""
        if not self.config.proxy_pass:
            log.error("HTTP Proxy: PROXY_PASS is required but not set")
            return

        log.info("Starting HTTP Proxy server in namespace...")

        cmd = [
            "ip", "netns", "exec", self.config.netns,
            sys.executable, "-m", "mole_pkg.services.proxy_main",
            "--bind", self.config.proxy_bind,
            "--port", str(self.config.proxy_port),
            "--user", self.config.proxy_user,
            "--veth-host-ip", self.config.veth_host_ip,
            "--veth-vpn-ip", self.config.veth_vpn_ip,
        ]

        # Pass password via environment variable (not visible in process list)
        env = self._get_subprocess_env()
        env["MOLE_PROXY_PASS"] = self.config.proxy_pass

        self._proxy_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        log.info(f"Proxy server started on {self.config.proxy_bind}:{self.config.proxy_port} (PID: {self._proxy_proc.pid})")

    def _stop_subprocess(self, proc: Optional[subprocess.Popen], name: str):
        """Stop a subprocess gracefully"""
        if proc is None:
            return

        if proc.poll() is None:  # Still running
            log.info(f"Stopping {name} server (PID: {proc.pid})...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                log.warning(f"{name} server did not stop gracefully, killing...")
                proc.kill()
                proc.wait()
            log.info(f"{name} server stopped")

    async def _cleanup(self):
        """Cleanup all resources"""
        if self._keepalive_task:
            self._keepalive_task.cancel()
        if self._watchdog_task:
            self._watchdog_task.cancel()
        if self._restart_watcher_task:
            self._restart_watcher_task.cancel()

        # Stop service subprocesses
        self._stop_subprocess(self._api_proc, "API")
        self._stop_subprocess(self._proxy_proc, "Proxy")
        self._stop_subprocess(self._dns_proc, "DNS")

        # Bring down VPN
        disconnect_vpn(self.config)
        log.info("Cleanup complete")

    def _write_state_files(self):
        """Write state to files for API server to read"""
        state_dir = Path(self.config.state_dir)

        if self.state.server_ip:
            secure_write_file(state_dir / 'server_ip', self.state.server_ip)
        if self.state.server_hostname:
            secure_write_file(state_dir / 'hostname', self.state.server_hostname)
        if self.state.server_vip:
            secure_write_file(state_dir / 'server_vip', self.state.server_vip)
        if self.state.peer_ip:
            secure_write_file(state_dir / 'peer_ip', self.state.peer_ip)
        if self.state.port:
            secure_write_file(state_dir / 'port', str(self.state.port))

    async def _full_renewal(self) -> bool:
        """Full VPN renewal process"""
        log.info("Starting full renewal...")

        old_server_ip = self.state.server_ip

        # Step 1: Authenticate
        if not await self.provider.authenticate():
            return False

        # Step 2: Get server
        if not await self.provider.get_server():
            return False

        # Step 3: Register WireGuard
        if not await self.provider.register_wireguard():
            return False

        # Step 4: Connect VPN
        if not await self._connect_vpn(old_server_ip):
            return False

        # Step 5: Setup port forwarding (if enabled)
        if self.config.port_forward:
            if not await self.provider.setup_port_forward():
                return False

            # Step 6: Update torrent client interface and port (if configured)
            # Retry with delay since torrent client may still be starting up
            if self.torrent:
                await self._update_torrent_client()

            log.info(f"Renewal complete! Server: {self.state.server_hostname}, Port: {self.state.port}")
        else:
            log.info(f"Renewal complete! Server: {self.state.server_hostname} (port forwarding disabled)")

        # Write state files for API to read
        self._write_state_files()

        return True

    async def _connect_vpn(self, old_server_ip: Optional[str]) -> bool:
        """Establish VPN connection"""
        log.info("Connecting VPN...")

        netns = self.config.netns

        # Bring down existing connection
        run_in_netns(["wg-quick", "down", "mole"], netns, check=False)

        # Allow traffic to VPN server IP through the kill switch
        allow_vpn_server_ip(self.config, self.state.server_ip, old_server_ip)

        # Update routes
        if old_server_ip:
            run_in_netns(["ip", "route", "del", old_server_ip, "via", self.config.veth_host_ip], netns, check=False)

        run_in_netns([
            "ip", "route", "add", self.state.server_ip,
            "via", self.config.veth_host_ip, "dev", "veth-vpn"
        ], netns, check=False)

        # Bring up WireGuard
        result = run_in_netns(["wg-quick", "up", self.config.wg_conf], netns, check=False)
        if result.returncode != 0:
            log.error(f"Failed to bring up WireGuard: {sanitize_for_log(result.stderr)}")
            return False

        await asyncio.sleep(5)

        # Verify connection
        result = run_in_netns(["ping", "-c", "1", "-W", "5", self.state.server_vip], netns, check=False)
        if result.returncode != 0:
            log.warning("VPN connectivity check failed, but continuing...")

        self.state.connected = True
        log.info("VPN connected")
        return True

    async def _keepalive_loop(self):
        """Port forwarding keepalive loop"""
        if not self.config.port_forward:
            log.info("Port forwarding disabled, keepalive loop not needed")
            return

        log.info("Keepalive loop started")

        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.keepalive_interval)

                if self.state.port_payload and self.state.connected:
                    if await self.provider.refresh_port_forward():
                        log.info(f"Port {self.state.port} keepalive OK")
                    else:
                        log.warning("Port keepalive failed")

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Keepalive error: {e}")

    async def _watchdog_loop(self):
        """VPN health monitoring loop"""
        log.info("Watchdog loop started")
        failures = 0

        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.watchdog_interval)

                if await self._check_health():
                    if failures > 0:
                        log.info(f"VPN recovered after {failures} failures")
                    failures = 0
                else:
                    failures += 1
                    log.warning(f"Health check failed ({failures}/{self.config.watchdog_max_failures})")

                    if failures >= self.config.watchdog_max_failures:
                        log.warning("Max failures reached, attempting recovery...")
                        await self._full_renewal()
                        failures = 0

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Watchdog error: {e}")

    async def _restart_watcher_loop(self):
        """Watch for restart triggers from API"""
        log.info("Restart watcher started")
        trigger_file = Path(self.config.state_dir) / 'restart_trigger'
        last_mtime = 0

        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(2)  # Check every 2 seconds

                try:
                    mtime = trigger_file.stat().st_mtime
                    if mtime > last_mtime:
                        last_mtime = mtime
                        log.info("Restart trigger detected from API")
                        try:
                            trigger_file.unlink()  # Remove trigger
                        except FileNotFoundError:
                            pass  # Already deleted by another process
                        await self._full_renewal()
                except FileNotFoundError:
                    pass  # Trigger file doesn't exist, nothing to do

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Restart watcher error: {e}")

    async def _check_health(self) -> bool:
        """Check VPN connection health"""
        try:
            netns = self.config.netns

            # Check interface
            result = run_in_netns(["ip", "link", "show", "mole"], netns, check=False)
            if result.returncode != 0:
                return False

            # Check handshake age
            result = run_in_netns(["wg", "show", "mole", "latest-handshakes"], netns, check=False)
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    handshake_ts = int(parts[1])
                    if handshake_ts == 0:
                        return False
                    age = int(datetime.now().timestamp()) - handshake_ts
                    if age > 180:
                        return False

            # Check VPN server ping (works for both PIA and ProtonVPN)
            if self.state.server_vip:
                result = run_in_netns(["ping", "-c", "1", "-W", "5", self.state.server_vip], netns, check=False)
                if result.returncode != 0:
                    return False

            return True

        except Exception as e:
            log.error(f"Health check error: {e}")
            return False

    async def _update_torrent_client(self, max_retries: int = 10, retry_delay: float = 3.0, allow_restart: bool = True):
        """Update torrent client with new interface and port.

        Retries with delay to handle cases where the torrent client
        is still starting up (e.g., after MOLE service restart).
        Falls back to restarting the service if API updates fail.

        Args:
            max_retries: Maximum number of API update attempts
            retry_delay: Seconds between retries
            allow_restart: If True, restart service as fallback (prevents recursion)
        """
        if not self.torrent:
            return

        interface_name = "mole"
        interface_address = self.state.peer_ip

        if not interface_address:
            log.warning("No peer IP available, skipping torrent client update")
            return

        for attempt in range(1, max_retries + 1):
            try:
                # Try to update interface binding
                if await self.torrent.set_interface(interface_name, interface_address):
                    # Interface updated, now set port
                    if self.state.port:
                        await self.torrent.set_listen_port(self.state.port)
                    log.info(f"Torrent client updated: interface={interface_name}, port={self.state.port}")
                    return
                else:
                    log.warning(f"Torrent client update attempt {attempt}/{max_retries} failed")

            except Exception as e:
                error_msg = str(e)
                if "Connection refused" in error_msg or "timed out" in error_msg.lower():
                    if attempt < max_retries:
                        log.info(f"Torrent client not ready (attempt {attempt}/{max_retries}), retrying in {retry_delay}s...")
                        await asyncio.sleep(retry_delay)
                        continue
                log.error(f"Torrent client update error: {e}")

            if attempt < max_retries:
                await asyncio.sleep(retry_delay)

        # Fallback: restart torrent client service if API updates failed
        if allow_restart:
            log.warning(f"API update failed after {max_retries} attempts, restarting torrent client service...")
            await self._restart_torrent_service()
        else:
            log.error(f"Failed to update torrent client after {max_retries} attempts (restart already attempted)")

    async def _restart_torrent_service(self):
        """Restart qBittorrent service as fallback when API update fails."""
        try:
            result = run_cmd(["systemctl", "restart", "qbittorrent-mole"], check=False)
            if result.returncode == 0:
                log.info("Torrent client service restarted successfully")
                # Wait for service to start, then try API update again (no further restart)
                await asyncio.sleep(15)
                await self._update_torrent_client(max_retries=3, retry_delay=5.0, allow_restart=False)
            else:
                log.error(f"Failed to restart torrent client service: {result.stderr}")
        except Exception as e:
            log.error(f"Error restarting torrent client service: {e}")
