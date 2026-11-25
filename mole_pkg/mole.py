"""
MOLE - Main Orchestrator

Manages VPN connection and spawns services in the VPN namespace.
"""

import asyncio
import ipaddress
import os
import signal
import subprocess
import sys
import time
import random
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional, List, cast

from . import __version__
from .config import Config
from .constants import DEFAULT_CONFIG_FILE
from .network import async_setup_namespace, async_disconnect_vpn, async_allow_vpn_server_ip, ValidationGate
from .validation import (Attempt, ExitValidator, AuthorizationDenied, configuration_digest,
                         ValidationStageError, VALIDATION_STAGES)
from .providers import PIAProvider, ProtonProvider
from .services import QBittorrentClient
from .utils import (
    VPNState,
    VPNProvider,
    append_ring_buffer,
    atomic_write_state,
    increment_counter,
    increment_dict_counter,
    log,
    run_cmd,
    run_in_netns,
    async_run_in_netns,
    async_run_command,
    handshake_timestamp,
    read_wg_peer_key,
    write_runtime_readiness,
    sanitize_for_log,
    secure_write_file,
    _process_identity,
)


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
        self.state.recovery_mode = self.config.proton_recovery_mode
        self.state.forwarding_required = self.config.port_forward
        self.state.client_required = self.config.torrent_client.lower() not in ('none', 'disabled', '')
        self.provider = get_vpn_provider(self.config, self.state)
        self.torrent = get_torrent_client(self.config)
        self.shutdown_event = asyncio.Event()
        self._torrent_update_lock = None
        self._torrent_sync_task = None
        self._listener_task = None
        self._installed_server_ip = None
        self._installed_peer_key = None
        self._installed_generation = None
        self._renewal_task = None
        self._mapping_recovery_task = None
        self._connecting = False
        self._mapping_failures = 0
        self._mapping_recovered = False
        self._recovery_not_before = 0
        self._recovery_exhaustions = 0
        self._keepalive_task = None
        self._watchdog_task = None
        self._restart_watcher_task = None
        self._validation_gate = None
        self._validation_attempt = None
        self._validation_task = None
        self._validator = None
        self._dns_repair_after = 0.0
        self._dns_proc_identity: Optional[str] = None
        self._candidate_deadline = 0.0
        self._cycle_deadline = 0.0

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

        self.config.validate_proton_recovery()
        root, gate = None, None
        if self._validated_mode:
            from .validation import trusted_executable, validate_cgroup_root
            trusted_executable(self.config.get('PROTON_EXIT_VALIDATOR'))
            root = validate_cgroup_root(self.config.get('PROTON_VALIDATION_CGROUP_ROOT'))
            subnet = str(ipaddress.IPv4Address(self.config.veth_host_ip)) + '/32'
            gate = ValidationGate(self.config.netns, subnet)
            self._validation_gate = gate
            self._validator = ExitValidator(self.config, gate)
            namespaces = await async_run_command(['ip', 'netns', 'list'], 5)
            if self.config.netns in [line.split()[0] for line in namespaces.stdout.splitlines() if line.split()]:
                await gate.check_support(root)
                await gate.quarantine(None)

        # Setup network namespace
        await async_setup_namespace(self.config)
        if self._validated_mode:
            if gate is None or root is None:
                raise RuntimeError('validated recovery was not prepared')
            await gate.check_support(root)
            await gate.quarantine(None)

        # Start DNS server in namespace if enabled (must start BEFORE VPN connects)
        if self.config.dot_enabled:
            self._start_dns_server()
            await asyncio.sleep(0.5)

        # Lease maintenance must already run while initial client updates retry.
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())

        # Initial VPN setup
        if not await self._full_renewal():
            log.error("Initial setup failed, will retry...")

        # Start background tasks
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

    @property
    def _validated_mode(self):
        return self.config.get('PROTON_RECOVERY_MODE', 'legacy') == 'validated'

    def _validation_config_digest(self):
        return configuration_digest(self.config)

    async def _stop_validation(self):
        self.state.authorization_ready = self.state.gate_open = False
        self.state.authorization_deadline = self.state.gate_verification_deadline = 0
        self._publish_readiness()
        task = getattr(self, '_validation_task', None)
        if task is not None and task is not asyncio.current_task():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self._validation_task = None
        gate = getattr(self, '_validation_gate', None)
        attempt = getattr(self, '_validation_attempt', None)
        if gate is not None and attempt is not None:
            try:
                await gate.revoke(attempt)
            except Exception:
                await async_disconnect_vpn(self.config)
                raise RuntimeError('validation gate could not be closed') from None
        self.state.authorization_ready = self.state.gate_open = False
        self._validation_attempt = None

    async def _before_recovery_change(self, candidates, scope):
        attempt = getattr(self, '_validation_attempt', None)
        if attempt is None:
            return
        identity = ProtonProvider.candidate_identity(attempt.candidate)
        eligible = any(ProtonProvider.candidate_identity(c) == identity for c in candidates)
        if scope != getattr(self.provider, '_validated_scope', None) or not eligible:
            # Drain the only refresh owner and close before publishing a new
            # pool/rejection. Its in-flight grant cannot overtake invalidation.
            await self._stop_validation()
            self.state.connected = self.state.tunnel_ready = False
            self.state.tunnel_deadline = 0

    async def _reconcile_current_permission(self):
        attempt = getattr(self, '_validation_attempt', None)
        if attempt is not None and not cast(ProtonProvider, self.provider).authorization_current(attempt.candidate):
            await self._stop_validation()
            self.state.connected = self.state.tunnel_ready = False
            self.state.tunnel_deadline = 0

    async def _begin_validated_attempt(self):
        await self._stop_validation()
        gate, validator = self._validation_gate, self._validator
        if gate is None or validator is None:
            raise RuntimeError('validated recovery was not prepared')
        server = cast(ProtonProvider, self.provider)._selected_server
        if server is None:
            raise RuntimeError('validated candidate unavailable')
        deadline = time.monotonic() + 20
        revision = await validator.describe(self._validation_config_digest(), deadline)
        attempt = Attempt(_process_identity(os.getpid()), self.state.generation,
                          secrets.token_hex(32), server,
                          revision, getattr(self, '_candidate_deadline', 0) or time.monotonic() + 90)
        await gate.quarantine(attempt)
        self._validation_attempt = attempt

    async def _validated_transport_evidence(self, attempt):
        if (attempt != self._validation_attempt or attempt.generation != self.state.generation or
                attempt.process_identity != _process_identity(os.getpid())):
            raise RuntimeError('stale transport identity')
        for query, expected in [('peers', attempt.candidate['public_key']),
                                ('endpoints', attempt.candidate['public_key'] + '\t' +
                                 attempt.candidate['entry_ip'] + ':51820')]:
            result = await async_run_in_netns(['wg', 'show', 'mole', query], self.config.netns, 2)
            if result.returncode or result.stdout.strip() != expected:
                raise RuntimeError('installed peer changed')
        mark = await async_run_in_netns(['wg', 'show', 'mole', 'fwmark'], self.config.netns, 2)
        if mark.returncode or mark.stdout.strip().lower() not in ('0xca6c', '51820'):
            raise RuntimeError('unexpected WireGuard mark')
        result = await async_run_in_netns(['wg', 'show', 'mole', 'latest-handshakes'], self.config.netns, 2)
        if result.returncode or handshake_timestamp(result.stdout, attempt.candidate['public_key'],
                                                  time.time(), self._attempt_wall) is None:
            raise RuntimeError('fresh intended handshake unavailable')
        # This follows a successful bound HTTPS observation in the same round.
        return time.monotonic() + 120

    async def _validate_current_attempt(self):
        attempt = self._validation_attempt
        gate, validator = self._validation_gate, self._validator
        provider = cast(ProtonProvider, self.provider)
        deadline = time.monotonic() + 20
        stage = 'identity'
        try:
            if (gate is None or validator is None or attempt is None or attempt.generation != self.state.generation or
                    attempt.process_identity != _process_identity(os.getpid()) or
                    not provider.authorization_current(attempt.candidate)):
                raise RuntimeError('stale validation identity')
            stage = 'policy'
            revision = await validator.describe(self._validation_config_digest(), deadline)
            if revision != attempt.policy_revision:
                raise RuntimeError('authorization policy changed')
            stage = 'round'
            round_ = await gate.prepare_round(attempt)
            stage = 'validation'
            evidence = await validator.validate(attempt, round_, self._validated_transport_evidence, deadline)
            stage = 'identity'
            if (attempt != self._validation_attempt or attempt.generation != self.state.generation or
                    self.shutdown_event.is_set() or not provider.authorization_current(attempt.candidate)):
                raise RuntimeError('late validation result')
            stage = 'grant'
            await gate.authorize(attempt, round_, evidence,
                current_check=lambda: provider.authorization_current(attempt.candidate))
            stage = 'readback'
            if not await gate.verify_open(attempt):
                raise RuntimeError('permission readback failed')
            self.state.authorization_ready = self.state.gate_open = True
            self.state.recovery_mode = 'validated'
            self.state.authorization_deadline = gate.deadline
            self.state.gate_verification_deadline = min(gate.deadline, time.monotonic() + 60)
            self.state.connected = self.state.tunnel_ready = True
            self.state.tunnel_deadline = evidence['transport_deadline']
            self.state.recovery_reason = 'none'
            self.state.last_error = ''
            return True
        except (Exception, asyncio.CancelledError) as error:
            if isinstance(error, ValidationStageError):
                stage = error.stage if error.stage in VALIDATION_STAGES else 'validation'
            outcome = ('cancelled' if isinstance(error, asyncio.CancelledError) else
                       'denied' if isinstance(error, AuthorizationDenied) else 'failed')
            log.warning('Validation %s at stage=%s', outcome, stage)
            self.state.authorization_ready = self.state.gate_open = False
            self.state.authorization_deadline = 0
            self.state.recovery_reason = ('authorization_denied' if isinstance(error, AuthorizationDenied)
                                          else 'authorization_unknown')
            self.state.last_error = 'validation_failed'
            if attempt is not None and gate is not None:
                try:
                    await gate.revoke(attempt)
                except Exception:
                    log.warning('Validation failed at stage=revoke')
                    await async_disconnect_vpn(self.config)
                    self.state.recovery_reason = 'enforcement_unavailable'
            if isinstance(error, asyncio.CancelledError):
                raise
            return False
        finally:
            self._publish_readiness()

    async def _validation_refresh_loop(self):
        while not self.shutdown_event.is_set():
            started = time.monotonic()
            if not await self._validate_current_attempt():
                self._recovery_not_before = time.monotonic()
                return
            await self._check_dns_health()
            await asyncio.sleep(max(0, started + 30 - time.monotonic()))

    def _configured_resolvers(self):
        path = Path('/etc/netns') / self.config.netns / 'resolv.conf'
        servers = []
        for line in path.read_text().splitlines():
            fields = line.split('#', 1)[0].split()
            if len(fields) == 2 and fields[0] == 'nameserver':
                servers.append(str(ipaddress.IPv4Address(fields[1])))
        return servers[:3]

    async def _probe_dns(self):
        from .validation import bounded_json_command
        try:
            servers = self._configured_resolvers()
            local = str(ipaddress.IPv4Address(self.config.dot_bind))
            port = self.config.dot_port if self.config.dot_enabled and (
                local in servers or local == '0.0.0.0' and '127.0.0.1' in servers) else 53
            result = await bounded_json_command(['ip', 'netns', 'exec', self.config.netns,
                sys.executable, '-m', 'mole_pkg.validation_worker', 'dns'],
                dict(servers=servers, port=port), 3)
            return result.get('dns_ready') is True
        except (OSError, ValueError, RuntimeError):
            return False

    async def _repair_dns_worker(self):
        if not self.config.dot_enabled or time.monotonic() < getattr(self, '_dns_repair_after', 0):
            return False
        try:
            servers = self._configured_resolvers()
            bind = self.config.dot_bind
            if bind not in servers and not (bind == '0.0.0.0' and '127.0.0.1' in servers):
                return False
        except (OSError, ValueError):
            return False
        self._dns_repair_after = time.monotonic() + 300

        async def repair():
            proc = getattr(self, '_dns_proc', None)
            if proc is not None:
                self._signal_dns_group(proc, signal.SIGTERM)
                until = time.monotonic() + 2
                while proc.poll() is None and time.monotonic() < until:
                    await asyncio.sleep(.05)
                # Kill descendants even if the main process exited gracefully.
                self._signal_dns_group(proc, signal.SIGKILL)
                while proc.poll() is None:
                    await asyncio.sleep(.05)
            self._start_dns_server(repair_cached=True)
            proc = self._dns_proc
            if proc is None:
                return False
            while not self.shutdown_event.is_set():
                if proc.poll() is not None:
                    return False
                if await self._probe_dns():
                    return True
                await asyncio.sleep(.1)
            return False
        try:
            return await asyncio.wait_for(repair(), 9)
        except (OSError, RuntimeError, asyncio.TimeoutError, asyncio.CancelledError) as error:
            proc = getattr(self, '_dns_proc', None)
            if proc is not None:
                self._signal_dns_group(proc, signal.SIGKILL)
                until = time.monotonic() + 1
                while proc.poll() is None and time.monotonic() < until:
                    await asyncio.sleep(.02)
            if isinstance(error, asyncio.CancelledError):
                raise
            return False

    def _signal_dns_group(self, proc, sig):
        identity = getattr(self, '_dns_proc_identity', None)
        if identity is None:
            raise RuntimeError('DNS process group ownership is unknown')
        try:
            current = _process_identity(proc.pid)
        except FileNotFoundError:
            pass  # The owned group's descendants can outlive its leader.
        else:
            if current != identity:
                raise RuntimeError('DNS process group leader identity changed')
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass

    async def _check_dns_health(self):
        if (not getattr(self.state, 'authorization_ready', False) or
                not getattr(self.state, 'gate_open', False) or
                time.monotonic() >= getattr(self.state, 'authorization_deadline', 0)):
            self.state.dns_ready = None
            return False
        ready = await self._probe_dns()
        if not ready and await self._repair_dns_worker():
            ready = await self._probe_dns()
        self.state.dns_ready = bool(ready)
        self.state.dns_deadline = time.monotonic() + 65 if ready else 0
        if not ready:
            self.state.recovery_reason = 'dns_failed'
        self._publish_readiness()
        return bool(ready)

    def _get_subprocess_env(self) -> dict:
        """Get environment for subprocess with PYTHONPATH set"""
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        return env

    def _start_dns_server(self, repair_cached=False):
        """Start DNS server as subprocess in namespace"""
        log.info("Starting DNS server in namespace...")

        cmd = [
            "ip", "netns", "exec", self.config.netns,
            sys.executable, "-m", "mole_pkg.services.dns_main",
            "--bind", self.config.dot_bind,
            "--port", str(self.config.dot_port),
            "--upstream", self.config.dot_upstream,
            "--state-dir", self.config.state_dir,
            "--pool-size", str(self.config.dot_pool_size),
            "--query-timeout", str(self.config.dot_query_timeout),
            "--query-retries", str(self.config.dot_query_retries),
            "--retry-backoff-ms", str(self.config.dot_retry_backoff_ms),
        ]

        if self.config.dot_custom_server:
            cmd.extend(["--custom-server", self.config.dot_custom_server])
        if self.config.dot_custom_sni:
            cmd.extend(["--custom-sni", self.config.dot_custom_sni])
        if self.config.dot_block_ads:
            cmd.append("--block-ads")
        if self.config.dot_block_malware:
            cmd.append("--block-malware")
        if self.config.dot_block_tracking:
            cmd.append("--block-tracking")
        if not self.config.dot_caching:
            cmd.append("--no-caching")
        if repair_cached:
            cmd.append('--repair-cached')
        if self.config.dot_cache_ttl:
            cmd.extend(["--cache-ttl", str(self.config.dot_cache_ttl)])

        self._dns_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=self._get_subprocess_env(),
            start_new_session=True,
        )
        self._dns_proc_identity = _process_identity(self._dns_proc.pid)
        log.info(f"DNS server started (PID: {self._dns_proc.pid})")

    def _start_api_server(self):
        """Start API server as subprocess in namespace"""
        log.info("Starting API server in namespace...")

        bind_addr = self.config.http_api_bind
        # Defense in depth — cmd_run calls validate_config before instantiating
        # Mole, so this branch is only reachable if validation was bypassed
        # (e.g. running Mole directly from a script). Refusing here is safer
        # than silently spawning an unauthenticated API server.
        if self.config.http_api_auth_required() and not self.config.http_api_key:
            raise RuntimeError(
                f"HTTP API auth required (HTTP_API_REQUIRE_AUTH="
                f"{self.config.http_api_require_auth}, bind='{bind_addr}') but "
                f"HTTP_API_KEY is empty. Generate a key with 'sudo mole "
                f"api-key generate', or set HTTP_API_REQUIRE_AUTH=false to opt "
                f"out (not recommended for non-loopback binds)."
            )
        if (
            self.config.http_api_require_auth == 'false'
            and not self.config.http_api_key
            and bind_addr not in ('127.0.0.1', 'localhost', '::1', '[::1]')
        ):
            log.warning(
                f"HTTP API on '{bind_addr}' is unauthenticated "
                f"(HTTP_API_REQUIRE_AUTH=false, no HTTP_API_KEY). Operator's "
                f"choice; logging once for visibility."
            )

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

        if name == 'DNS':
            self._signal_dns_group(proc, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            self._signal_dns_group(proc, signal.SIGKILL)
            proc.wait(timeout=1)
            return

        if proc.poll() is None:  # Still running
            log.info(f"Stopping {name} server (PID: {proc.pid})...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                log.warning(f"{name} server did not stop gracefully, killing...")
                proc.kill()
                proc.wait(timeout=1)
            log.info(f"{name} server stopped")

    async def _cleanup(self):
        """Cleanup all resources."""
        if self._validated_mode:
            await self._stop_validation()
        tasks = [task for task in (
            self._keepalive_task, self._watchdog_task, self._restart_watcher_task,
            getattr(self, '_torrent_sync_task', None),
            getattr(self, '_mapping_recovery_task', None),
            getattr(self, '_renewal_task', None),
            getattr(self, '_listener_task', None),
        ) if task is not None]
        for task in tasks:
            task.cancel()
        # In-flight HTTP writes and temporary port restoration must finish
        # before stopping the tunnel they depend on.
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception):
                log.warning(f"Background task cleanup failed: {sanitize_for_log(str(result))}")

        # Stop service subprocesses
        self._stop_subprocess(self._api_proc, "API")
        self._stop_subprocess(self._proxy_proc, "Proxy")
        self._stop_subprocess(self._dns_proc, "DNS")

        # Run pre-disconnect hook while the VPN namespace is still live
        await self._run_hook(self.config.post_disconnect_hook, "POST_DISCONNECT_HOOK")

        # Invalidate evidence before bringing down the VPN.
        self.state.generation += 1
        self.state.connected = self.state.tunnel_ready = self.state.forwarding_ready = self.state.client_ready = False
        self.state.tunnel_deadline = self.state.port_deadline = 0
        self.state.last_error = 'stopped'
        self._publish_readiness()
        # Bring down VPN
        await async_disconnect_vpn(self.config)
        log.info("Cleanup complete")

    def _write_state_files(self):
        """Write state to files for API server to read"""
        state_dir = Path(self.config.state_dir)

        if self.state.server_ip:
            secure_write_file(state_dir / 'server_ip', self.state.server_ip)
        if self.state.server_hostname:
            secure_write_file(state_dir / 'hostname', self.state.server_hostname)
        if self.state.server_country:
            secure_write_file(state_dir / 'server_country', self.state.server_country)
        if self.state.server_vip:
            secure_write_file(state_dir / 'server_vip', self.state.server_vip)
        if self.state.peer_ip:
            secure_write_file(state_dir / 'peer_ip', self.state.peer_ip)
        if self.state.port:
            secure_write_file(state_dir / 'port', str(self.state.port))

    async def _full_renewal(self, reason: str = 'scheduled') -> bool:
        active = getattr(self, '_renewal_task', None)
        if active is not None and not active.done():
            return await asyncio.shield(active)
        if time.monotonic() < getattr(self, '_recovery_not_before', 0):
            return False
        operation = self._full_renewal_owned(reason)
        if self._validated_mode:
            operation = asyncio.wait_for(operation, self.config.proton_recovery_cycle_timeout)
        task = asyncio.create_task(operation)
        self._renewal_task = task
        try:
            return await task
        finally:
            if task.done() and self._renewal_task is task:
                self._renewal_task = None

    def _defer_recovery(self):
        count = min(getattr(self, '_recovery_exhaustions', 0), 4)
        delay = min(300, 30 * (2 ** count) + random.uniform(0, 5))
        self._recovery_not_before = time.monotonic() + delay
        self._recovery_exhaustions = count + 1
        if self._validated_mode:
            policy = cast(ProtonProvider, self.provider)._policy()
            earliest = policy.next_eligible_at(policy._resolved, time.monotonic())
            if earliest is not None and earliest > time.monotonic():
                self._recovery_not_before = max(self._recovery_not_before, earliest)
                scheduling_reason = 'pool_cooldown'
            else:
                scheduling_reason = 'no_eligible_candidates'
            if self.state.recovery_reason in ('none', 'connecting', 'pool_cooldown', 'no_eligible_candidates'):
                self.state.recovery_reason = scheduling_reason

    def _mapping_result(self, success: bool) -> bool:
        if success:
            self._mapping_failures = 0
            self._mapping_recovered = False
            self._recovery_not_before = 0
            self._recovery_exhaustions = 0
            if not isinstance(self.provider, ProtonProvider) and self.state.port_expires:
                expiry = self.state.port_expires
                remaining = (expiry - datetime.now(expiry.tzinfo)).total_seconds()
                self.state.port_deadline = time.monotonic() + max(0, min(remaining, self.config.keepalive_interval * 2))
                self.state.forwarding_ready = remaining > 0
            if self.state.connected:
                self.state.last_error = ''
            return False
        self._mapping_failures = getattr(self, '_mapping_failures', 0) + 1
        if self.state.connected or not self.state.last_error:
            self.state.last_error = 'forwarding_unavailable'
        return self._mapping_failures >= 3 and not getattr(self, '_mapping_recovered', False)

    async def _attempt_selected_server(self, old_server_ip):
        if not await self.provider.register_wireguard():
            return False
        self._connecting = True
        if isinstance(self.provider, ProtonProvider):
            server = self.provider._selected_server
            self.state.server_ip = server['entry_ip']
            self.state.server_hostname = server['hostname']
            self.state.server_country = server.get('country')
            self.state.server_vip = server['entry_ip']
            self.state.peer_ip = '10.2.0.2'
        try:
            if not await self._connect_vpn(old_server_ip):
                return False
        finally:
            self._connecting = False
        if self.config.port_forward:
            self._mapping_result(await self.provider.setup_port_forward())
        self._start_torrent_sync(retry=True)
        if isinstance(self.provider, ProtonProvider):
            self._installed_server = dict(self.provider._selected_server)
            atomic_write_state(Path(self.config.state_dir), 'server_name',
                               self._installed_server['name'])
        return True

    async def _recover_candidates(self, reason):
        proton = isinstance(self.provider, ProtonProvider)
        enabled = proton and self.provider.failover_enabled
        limit = self.config.proton_failover_max_attempts if enabled else 1
        installed = getattr(self, '_installed_server', None) or (self.provider._selected_server if proton else None)
        previous = dict(installed) if proton and installed and self.state.tunnel_ready else None
        attempted = set()
        cycle_deadline = getattr(self, '_cycle_deadline', 0) or time.monotonic() + 300
        if reason == 'mapping' and not self._validated_mode:
            if getattr(self, '_mapping_recovered', False):
                return self.state.connected
            self._mapping_recovered = True
            if previous and await self.provider.restore_server(previous):
                attempted.add(self.provider._selected_server['entry_ip'])
                if await self._attempt_selected_server(self.state.server_ip):
                    if self.state.forwarding_ready:
                        self.provider.record_server_success()
                        return True
                self.provider.record_server_failure('mapping')

        while len(attempted) < limit:
            old_server_ip = self.state.server_ip
            if not await self.provider.get_server():
                break
            address = self.provider._selected_server['entry_ip'] if proton else self.state.server_ip
            if address in attempted:
                break
            attempted.add(address)
            if self._validated_mode:
                remaining_attempts = max(1, limit - len(attempted) + 1)
                budget = min(90, max(0, cycle_deadline - time.monotonic()) / remaining_attempts)
                if budget <= 0:
                    break
                self._candidate_deadline = time.monotonic() + budget
                try:
                    ready = await asyncio.wait_for(self._attempt_selected_server(old_server_ip), budget)
                except asyncio.TimeoutError:
                    await self._stop_validation()
                    ready = False
            else:
                ready = await self._attempt_selected_server(old_server_ip)
            if ready:
                if proton:
                    previous = dict(self.provider._selected_server)
                if not self.config.port_forward or self.state.forwarding_ready or reason != 'mapping':
                    if proton:
                        self.provider.record_server_success()
                    return True
            if proton:
                self.provider.record_server_failure('mapping' if ready else 'readiness')
            if not enabled:
                break

        # Keep a verified private tunnel even when every mapping option failed.
        still_verified = self.state.tunnel_ready
        if self._validated_mode:
            attempt, gate = getattr(self, '_validation_attempt', None), self._validation_gate
            still_verified = bool(still_verified and attempt is not None and gate is not None and
                cast(ProtonProvider, self.provider).authorization_current(attempt.candidate) and
                await gate.verify_open(attempt))
        if still_verified:
            self._defer_recovery()
            return True
        # One restoration is allowed only to a previously verified eligible
        # endpoint already counted in this bounded cycle.
        if not self._validated_mode and previous and previous['entry_ip'] in attempted:
            old_server_ip = self.state.server_ip
            if await self.provider.restore_server(previous):
                if await self._attempt_selected_server(old_server_ip):
                    self._defer_recovery()
                    return True
        self.state.connected = self.state.tunnel_ready = False
        self.state.last_error = 'approved_recovery_exhausted'
        self._defer_recovery()
        return False

    async def _full_renewal_owned(self, reason: str) -> bool:
        """Full VPN renewal process.

        Operationally instrumented: every renewal attempt increments either
        renewals_success_total or renewals_failure_total in $STATE_DIR, and
        on success persists last_renewal_success_ts plus
        last_renewal_duration_seconds. api_main exposes these as Prometheus
        counters/gauges so the daily renewal cadence is chartable and a
        rising failure rate is alertable. Counters survive process restart
        because they're plain text files.
        """
        log.info("Starting full renewal...")

        state_dir = Path(self.config.state_dir)
        renewal_start = time.time()
        success = False

        old_server_ip = self.state.server_ip

        try:
            # Step 1: Authenticate
            if self._validated_mode:
                self._cycle_deadline = time.monotonic() + self.config.proton_recovery_cycle_timeout
                cast(ProtonProvider, self.provider).before_recovery_change = self._before_recovery_change
            prepare = cast(ProtonProvider, self.provider).prepare_recovery if self._validated_mode else self.provider.authenticate
            if not await prepare():
                if self._validated_mode:
                    await self._reconcile_current_permission()
                self.state.last_error = 'authentication_failed'
                self._defer_recovery()
                return False

            if self._validated_mode:
                await self._reconcile_current_permission()

            if not await self._recover_candidates(reason):
                return False
            if not self.config.port_forward:
                self._recovery_not_before = self._recovery_exhaustions = 0

            # Run post-connect hook if configured
            if self.config.post_connect_hook:
                self.state.hook_ready = bool(await self._run_hook(self.config.post_connect_hook, "POST_CONNECT_HOOK"))

            # Write state files for API to read
            self._write_state_files()

            success = True
            return True
        finally:
            self._publish_readiness()
            duration = time.time() - renewal_start
            try:
                if success:
                    increment_counter(state_dir, 'renewals_success_total')
                    atomic_write_state(state_dir, 'last_renewal_success_ts', str(int(renewal_start + duration)))
                    atomic_write_state(state_dir, 'last_renewal_duration_seconds', f"{duration:.3f}")
                else:
                    increment_counter(state_dir, 'renewals_failure_total')
                # Per-event log for the renewal-detail table. Captures
                # whatever state we have at the moment of completion;
                # failed renewals legitimately have empty server/port.
                append_ring_buffer(
                    state_dir,
                    'renewals_recent.json',
                    {
                        'ts': int(renewal_start),
                        'duration_seconds': round(duration, 3),
                        'outcome': 'success' if success else 'failure',
                        'server': self.state.server_hostname or '',
                        'country': (self.state.server_country or '').upper(),
                        'endpoint_ip': self.state.server_ip or '',
                        'port': int(self.state.port or 0),
                    },
                )
            except Exception as e:
                # Never let metrics bookkeeping mask a real renewal outcome.
                log.warning(f"Failed to persist renewal metrics: {e}")

    async def _connect_vpn(self, old_server_ip: Optional[str]) -> bool:
        """Establish VPN connection"""
        log.info("Connecting VPN...")

        netns = self.config.netns
        old_server_ip = getattr(self, '_installed_server_ip', None) or old_server_ip
        self.state.generation += 1
        self.state.connected = self.state.tunnel_ready = self.state.forwarding_ready = self.state.client_ready = False
        self.state.tunnel_deadline = self.state.port_deadline = 0
        self.state.last_error = 'connecting'
        self.state.recovery_reason = 'connecting'
        self._publish_readiness()
        if self._validated_mode:
            await self._begin_validated_attempt()
        try:
            peer_key = read_wg_peer_key(self.config.wg_conf)
        except ValueError:
            self.state.last_error = 'invalid_peer_config'
            self._publish_readiness()
            return False

        # Bring down existing connection
        self._installed_peer_key = self._installed_generation = None
        try:
            await async_run_in_netns(["wg-quick", "down", "mole"], netns, timeout=30)

            # Allow traffic to VPN server IP through the kill switch.
            await async_allow_vpn_server_ip(self.config, self.state.server_ip, old_server_ip)

            # Update routes only after endpoint policy is reconciled.
            if old_server_ip:
                await async_run_in_netns(["ip", "route", "del", old_server_ip, "via", self.config.veth_host_ip], netns, timeout=10)

            route = await async_run_in_netns([
                "ip", "route", "replace", self.state.server_ip,
                "via", self.config.veth_host_ip, "dev", "veth-vpn"
            ], netns, timeout=10)
            if route.returncode != 0:
                raise RuntimeError('VPN endpoint route failed')
            self._installed_server_ip = self.state.server_ip

            # Bring up WireGuard.
            self._attempt_wall = int(time.time())
            result = await async_run_in_netns(["wg-quick", "up", self.config.wg_conf], netns, timeout=30)
        except (asyncio.TimeoutError, OSError, RuntimeError):
            self.state.last_error = 'wireguard_setup_failed'
            self.state.recovery_reason = 'transport_failed'
            self._publish_readiness()
            log.error('VPN setup command failed')
            return False
        if result.returncode != 0:
            self.state.last_error = 'wireguard_setup_failed'
            self.state.recovery_reason = 'transport_failed'
            self._publish_readiness()
            log.error("Failed to bring up WireGuard")
            return False

        self._installed_peer_key = peer_key
        self._installed_generation = self.state.generation

        if self._validated_mode:
            attempt = self._validation_attempt
            if attempt is None or peer_key != attempt.candidate['public_key']:
                raise RuntimeError('generated peer differs from validated candidate')
            ready = await self._validate_current_attempt()
            if ready:
                self._validation_task = asyncio.create_task(self._validation_refresh_loop())
        else:
            ready = await self._wait_for_readiness(peer_key, time.monotonic())
        if ready:
            log.info("VPN handshake and tunnel egress verified")
        return ready

    def _publish_readiness(self):
        self.state.next_retry_deadline = getattr(self, '_recovery_not_before', 0)
        try:
            write_runtime_readiness(Path(self.config.state_dir), self.state)
        except OSError:
            log.warning('Could not publish runtime readiness')

    async def _verify_transport(self, peer_key, deadline, not_before):
        for target in self.config.vpn_ready_probes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            timeout = min(5, remaining)
            try:
                response = await asyncio.wait_for(async_run_in_netns(
                    ['curl', '--silent', '--head', '--output', '/dev/null', '--write-out', '%{http_code}',
                     '--interface', 'mole', '--noproxy', '*', '--proto', '=https',
                     '--max-time', str(timeout), target], self.config.netns, timeout), timeout)
                if response.returncode != 0 or not response.stdout.strip().isdigit() or not 100 <= int(response.stdout.strip()) <= 599:
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                handshake = await asyncio.wait_for(async_run_in_netns(
                    ['wg', 'show', 'mole', 'latest-handshakes'], self.config.netns, min(5, remaining)), remaining)
                if handshake.returncode == 0 and handshake_timestamp(handshake.stdout, peer_key, time.time(), not_before) is not None:
                    return True
            except (OSError, asyncio.TimeoutError):
                continue
        return False

    async def _wait_for_readiness(self, peer_key: str, attempt_started: float) -> bool:
        deadline = attempt_started + self.config.vpn_ready_timeout
        generation = self.state.generation
        try:
            while time.monotonic() < deadline and generation == self.state.generation:
                if await self._verify_transport(peer_key, deadline, self._attempt_wall):
                    if generation != self.state.generation:
                        return False
                    self.state.connected = self.state.tunnel_ready = True
                    self.state.tunnel_deadline = time.monotonic() + max(90, 2 * self.config.watchdog_interval + 10)
                    self.state.last_error = ''
                    self._publish_readiness()
                    return True
                await asyncio.sleep(min(1, max(0, deadline - time.monotonic())))
        except asyncio.CancelledError:
            if generation != self.state.generation:
                raise
            self.state.connected = self.state.tunnel_ready = False
            self.state.last_error = 'readiness_cancelled'
            self._publish_readiness()
            raise
        if generation != self.state.generation:
            return False
        self.state.connected = self.state.tunnel_ready = False
        self.state.last_error = 'readiness_unproven'
        self._publish_readiness()
        return False

    def _installed_tunnel_current(self) -> bool:
        return bool(getattr(self, '_installed_peer_key', None)
                    and self.state.server_ip
                    and getattr(self, '_installed_generation', None) == self.state.generation
                    and getattr(self, '_installed_server_ip', None) == self.state.server_ip)

    def _can_maintain_forwarding(self) -> bool:
        if getattr(self, '_connecting', False):
            return False
        if self._validated_mode and (not getattr(self.state, 'gate_open', False) or
                                    time.monotonic() >= getattr(self.state, 'authorization_deadline', 0)):
            return False
        if isinstance(self.provider, ProtonProvider):
            # A failed HTTPS probe must not starve the installed peer's short lease.
            return self._installed_tunnel_current()
        return self.state.connected

    async def _keepalive_loop(self):
        """Port forwarding keepalive loop.

        Operationally instrumented: each refresh attempt increments either
        port_forward_renewals_success_total or port_forward_renewals_failure_total
        and on success persists last_port_forward_success_ts. api_main exposes
        these so a silently-failing NAT-PMP keepalive (port still configured
        but actually unforwarded) is alertable on staleness rather than only
        becoming visible when trackers report unreachable peer.
        """
        if not self.config.port_forward:
            log.info("Port forwarding disabled, keepalive loop not needed")
            return

        log.info("Keepalive loop started")

        state_dir = Path(self.config.state_dir)
        loop = asyncio.get_running_loop()
        next_refresh = loop.time() + self.config.keepalive_interval

        while not self.shutdown_event.is_set():
            try:
                if self._can_maintain_forwarding() and isinstance(self.provider, ProtonProvider):
                    next_refresh = min(next_refresh, loop.time() +
                                       self.provider.port_refresh_delay(self.config.keepalive_interval))
                # Notice a newly established short lease while initial client
                # synchronization is still running in another task.
                await asyncio.sleep(min(1, max(0, next_refresh - loop.time())))
                if loop.time() < next_refresh:
                    continue
                next_refresh = loop.time() + self.config.keepalive_interval

                # Retry initial mapping failures without requiring a tunnel reconnect.
                # port_payload is PIA-specific and must not gate Proton renewals.
                if self._can_maintain_forwarding():
                    generation = self.state.generation
                    if self.state.port:
                        refresh_ok = await self.provider.refresh_port_forward()
                    else:
                        refresh_ok = await self.provider.setup_port_forward()
                    if generation != self.state.generation:
                        continue
                    recovery_due = self._mapping_result(refresh_ok)
                    delay = self.config.keepalive_interval
                    if isinstance(self.provider, ProtonProvider):
                        delay = self.provider.port_refresh_delay(delay)
                    next_refresh = loop.time() + delay
                    if refresh_ok and self.torrent and self.state.connected:
                        # Client synchronization is supervised separately; a slow
                        # or failed API update does not mean the lease failed.
                        task = self._torrent_sync_task
                        if task is None or task.done():
                            task = asyncio.create_task(self._sync_torrent_binding())
                            self._torrent_sync_task = task
                            task.add_done_callback(self._torrent_sync_finished)
                    try:
                        country = (self.state.server_country or "").upper() or "unknown"
                        if refresh_ok:
                            increment_counter(state_dir, 'port_forward_renewals_success_total')
                            increment_dict_counter(state_dir, 'port_forward_renewals.json', country, 'success')
                            atomic_write_state(state_dir, 'last_port_forward_success_ts', str(int(time.time())))
                        else:
                            increment_counter(state_dir, 'port_forward_renewals_failure_total')
                            increment_dict_counter(state_dir, 'port_forward_renewals.json', country, 'failure')
                    except Exception as e:
                        log.warning(f"Failed to persist port-forward metrics: {e}")
                    if refresh_ok:
                        log.info(f"Port {self.state.port} keepalive OK")
                    else:
                        log.warning("Port keepalive failed")
                    self._publish_readiness()
                    task = getattr(self, '_mapping_recovery_task', None)
                    if recovery_due and (task is None or task.done()):
                        task = asyncio.create_task(self._full_renewal(reason='mapping'))
                        self._mapping_recovery_task = task
                        task.add_done_callback(self._recovery_finished)

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error(f"Keepalive error: {e}")

    def _torrent_sync_finished(self, task):
        if task.cancelled():
            return
        try:
            if task.result():
                log.debug("qBittorrent synchronization completed")
            else:
                log.warning("qBittorrent synchronization failed; will retry on next keepalive")
        except Exception as exc:
            log.warning(f"qBittorrent synchronization failed: {sanitize_for_log(str(exc))}")

    def _start_torrent_sync(self, retry=False):
        if not self.torrent:
            return
        active = getattr(self, '_torrent_sync_task', None)
        if active is None or active.done():
            operation = self._update_torrent_client(allow_restart=not self._validated_mode) if retry else self._sync_torrent_binding()
            task = asyncio.create_task(operation)
            self._torrent_sync_task = task
            task.add_done_callback(self._torrent_sync_finished)

    def _listener_finished(self, task):
        if not task.cancelled():
            try:
                task.result()
            except Exception:
                log.warning('Torrent listener supervision failed')

    def _recovery_finished(self, task):
        if not task.cancelled():
            try:
                task.result()
            except Exception:
                log.error('Coordinated VPN recovery failed')

    def _torrent_lock(self):
        # Python 3.8 locks capture their loop eagerly; construct only on use.
        if self._torrent_update_lock is None:
            self._torrent_update_lock = asyncio.Lock()
        return self._torrent_update_lock

    async def _sync_torrent_binding(self) -> bool:
        async with self._torrent_lock():
            while True:
                generation = self.state.generation
                address, port = self.state.peer_ip, self.state.port
                if not address:
                    log.warning("Cannot synchronize torrent binding without a tunnel address")
                    return False
                success = await self.torrent.set_interface("mole", address)
                if success and port:
                    success = await self.torrent.set_listen_port(port)
                if generation != self.state.generation:
                    return False
                if (address, port) == (self.state.peer_ip, self.state.port):
                    self.state.client_ready = bool(success)
                    self._publish_readiness()
                    return success
                # A renewal can change either target while HTTP is in flight.
                # Keep the writer lock and reconcile before reporting completion.
                log.debug("Torrent binding changed during synchronization; reconciling latest target")

    async def _watchdog_loop(self):
        """VPN health monitoring loop"""
        log.info("Watchdog loop started")
        failures = 0

        while not self.shutdown_event.is_set():
            try:
                await asyncio.sleep(self.config.watchdog_interval)

                if self._validated_mode and not getattr(self.state, 'gate_open', False):
                    # Once deferred, eligibility itself wakes recovery; do not
                    # accumulate a second watchdog failure threshold.
                    if time.monotonic() >= getattr(self, '_recovery_not_before', 0):
                        await self._full_renewal('readiness')
                    continue

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
        if self._validated_mode:
            attempt = self._validation_attempt
            gate = self._validation_gate
            current = (attempt is not None and gate is not None and attempt.generation == self.state.generation and
                       await gate.verify_open(attempt))
            self.state.gate_open = self.state.authorization_ready = bool(current)
            if current:
                self._supervise_torrent()
            self._publish_readiness()
            return bool(current)
        """Check VPN connection health"""
        try:
            peer_key = getattr(self, '_installed_peer_key', None)
            if not self._installed_tunnel_current():
                return False
            generation = self.state.generation
            ready = await self._verify_transport(peer_key, time.monotonic() + min(10, self.config.vpn_ready_timeout),
                                                 getattr(self, '_attempt_wall', 0))
            if generation != self.state.generation:
                return False
            self.state.connected = self.state.tunnel_ready = ready
            self.state.tunnel_deadline = time.monotonic() + max(90, 2 * self.config.watchdog_interval + 10) if ready else 0
            if not ready:
                self.state.last_error = 'health_unproven'
                self._publish_readiness()
                return False
            self._publish_readiness()

            self._supervise_torrent()

            return True

        except Exception as e:
            self.state.connected = self.state.tunnel_ready = False
            self.state.last_error = 'health_check_failed'
            self._publish_readiness()
            log.error("VPN health check failed")
            return False

    def _supervise_torrent(self):
        # Client work never owns or restarts the tunnel monitoring loop.
        if self.torrent:
            if not self.state.client_ready:
                self._start_torrent_sync()
            task = getattr(self, '_listener_task', None)
            if self.state.port and (task is None or task.done()):
                task = asyncio.create_task(self._check_torrent_listener())
                self._listener_task = task
                task.add_done_callback(self._listener_finished)

    async def _check_torrent_listener(self):
        """Check if torrent client listener is bound; fix via port toggle if not."""
        try:
            async with self._torrent_lock():
                generation = self.state.generation
                status = await self.torrent.get_connection_status()
                if generation != self.state.generation:
                    return
                if status == "disconnected":
                    log.warning("Torrent listener is disconnected, attempting port toggle fix")
                    await self.torrent._toggle_port(self.state.port)
        except Exception as e:
            log.error(f"Torrent listener check error: {e}")

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
            return True

        interface_name = "mole"
        interface_address = self.state.peer_ip

        if not interface_address:
            log.warning("No peer IP available, skipping torrent client update")
            return False

        for attempt in range(1, max_retries + 1):
            try:
                if await self._sync_torrent_binding():
                    log.info(f"Torrent client updated: interface={interface_name}, port={self.state.port}")
                    return True
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
            return await self._restart_torrent_service()
        else:
            log.error(f"Failed to update torrent client after {max_retries} attempts (restart already attempted)")
        return False

    async def _restart_torrent_service(self):
        """Restart qBittorrent service as fallback when API update fails."""
        try:
            result = await async_run_command(["systemctl", "restart", "qbittorrent-mole"], timeout=10)
            if result.returncode == 0:
                log.info("Torrent client service restarted successfully")
                # Wait for service to start, then try API update again (no further restart)
                await asyncio.sleep(15)
                return await self._update_torrent_client(max_retries=3, retry_delay=5.0, allow_restart=False)
            else:
                log.error('Failed to restart torrent client service')
        except Exception:
            log.error('Error restarting torrent client service')
        return False

    async def _run_hook(self, hook_path: str, hook_name: str) -> bool:
        """Run a hook script in the VPN namespace.

        The hook receives environment variables with connection info:
        - MOLE_VPN_IP: The VPN peer IP address
        - MOLE_SERVER_IP: The VPN server IP
        - MOLE_SERVER_HOSTNAME: The VPN server hostname
        - MOLE_PORT: The forwarded port (if enabled)
        """
        if not hook_path:
            return False

        hook_file = Path(hook_path)
        if not hook_file.exists():
            log.warning(f"{hook_name} not found: {hook_path}")
            return False

        if not os.access(hook_path, os.X_OK):
            log.warning(f"{hook_name} is not executable: {hook_path}")
            return False

        log.info(f"Running {hook_name}: {hook_path}")

        # Build environment with connection info
        env = os.environ.copy()
        env["MOLE_VPN_IP"] = self.state.peer_ip or ""
        env["MOLE_SERVER_IP"] = self.state.server_ip or ""
        env["MOLE_SERVER_HOSTNAME"] = self.state.server_hostname or ""
        env["MOLE_PORT"] = str(self.state.port) if self.state.port else ""

        try:
            result = await async_run_in_netns(
                [hook_path],
                self.config.netns,
                timeout=30,
                env=env
            )
            if result.returncode == 0:
                log.info(f"{hook_name} completed successfully")
                return True
            else:
                log.warning(f"{hook_name} exited with code {result.returncode}")
        except Exception:
            log.error(f"{hook_name} failed")
        return False
