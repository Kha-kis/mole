"""
MOLE Proton Provider - ProtonVPN integration

Uses proton.Session with TLS pinning disabled for compatibility.
Port forwarding uses NAT-PMP protocol.
"""

import asyncio
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

try:
    from proton import Session as ProtonAPISession
except ImportError:
    ProtonAPISession = None

from ..config import Config, validate_proton_client_version
from ..recovery import ApprovedServerPolicy
from ..utils import (
    VPNProvider,
    VPNState,
    log,
    run_cmd,
    run_in_netns,
    async_run_in_netns,
    async_run_command,
    sanitize_for_log,
    secure_write_file,
)

# Proton API configuration
PROTON_API_URL = "https://account.protonvpn.com/api"
PROTON_CLIENT_VERSION = "4.19.1"
PROTON_APP_VERSION = f"linux-vpn@{PROTON_CLIENT_VERSION}"
PROTON_USER_AGENT = f"ProtonVPN/{PROTON_CLIENT_VERSION} (Linux)"
SDK_API_OPERATIONS = {('/vpn/logicals', 'GET'),
                      ('/vpn/v2', 'GET'),
                      ('/vpn/v1/certificate/key/EC', 'GET'),
                      ('/vpn/v1/certificate', 'POST')}

SDK_FAILURE_KINDS = frozenset(('transient', 'credentials_rejected', 'compatibility',
                               'invalid_response', 'local_state'))


class SDKFailure(RuntimeError):
    """Finite, non-secret boundary between the SDK helper and recovery policy."""
    def __init__(self, kind):
        self.kind = kind if kind in SDK_FAILURE_KINDS else 'local_state'
        super().__init__('Proton operation: ' + self.kind)


class ProtonSessionWrapper:
    """Wrapper around proton.Session with persistence support"""

    def __init__(self, session_file: Path, client_version: str = PROTON_CLIENT_VERSION):
        self.session_file = session_file
        self._session: Optional[ProtonAPISession] = None
        version = validate_proton_client_version(client_version)
        self.app_version = f'linux-vpn@{version}'
        self.user_agent = f'ProtonVPN/{version} (Linux)'
        self.compatibility_rejected = False
        self.last_failure: Optional[Exception] = None

    def _classify_rejection(self, error: Exception) -> bool:
        if getattr(error, 'code', None) in (5003, '5003'):
            self.compatibility_rejected = True
            log.error('Proton rejected the configured client version; review PROTON_CLIENT_VERSION')
            return True
        return False

    def _create_session(self) -> ProtonAPISession:
        """Create a new Proton API session"""
        if ProtonAPISession is None:
            raise RuntimeError('Proton support requires the optional proton-client package')
        return ProtonAPISession(
            api_url=PROTON_API_URL,
            appversion=self.app_version,
            user_agent=self.user_agent,
            TLSPinning=False,  # Disable to avoid urllib3 compatibility issues
            timeout=30
        )

    def load(self) -> bool:
        """Load session from disk"""
        try:
            if self.session_file.exists():
                dump = json.loads(self.session_file.read_text())
                dump["appversion"] = self.app_version
                dump["User-Agent"] = self.user_agent
                self._session = ProtonAPISession.load(
                    dump,
                    TLSPinning=False,
                    timeout=30
                )
                log.debug("Loaded saved Proton session")
                return True
        except Exception:
            log.debug("Could not load saved Proton session")
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
        except Exception:
            log.warning("Could not save Proton session")

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
            self.last_failure = e
            if not self._classify_rejection(e):
                log.warning("Proton session refresh failed")
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
                self.last_failure = e
                if self._classify_rejection(e):
                    return False
                error_str = str(e).lower()
                # Check for rate limit indicators
                if "too many" in error_str or "rate" in error_str or "429" in error_str:
                    if attempt < max_retries:
                        log.warning(f"Rate limited, will retry with backoff")
                        continue
                    else:
                        log.error(f"Rate limited after {max_retries} retries. Wait before trying again.")
                        return False

                log.error("Proton authentication failed")
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
        self._mapping_lock = None
        self._recovery_policy = None
        self._sdk_lock = None
        self._validated_candidates: List[Dict[str, Any]] = []
        self._validated_scope: Optional[str] = None
        self._validated_deadline = 0
        self._active_preparation_pending = None
        self.before_recovery_change: Optional[Callable[[List[Dict[str, Any]], Optional[str]], Awaitable[None]]] = None
        self._effective_tier: int = self._tier

    async def _run_sdk_job(self, operation, endpoint='', method='GET', data=None) -> dict:
        if not ((operation in ('authenticate', 'load', 'refresh') and not endpoint and method == 'GET') or
                (operation == 'api' and (endpoint, method) in SDK_API_OPERATIONS)):
            raise ValueError('unsupported Proton operation')
        if self._sdk_lock is None:
            self._sdk_lock = asyncio.Lock()
        generation = self.state.generation
        async with self._sdk_lock:
            if generation != self.state.generation:
                raise RuntimeError('stale queued Proton operation rejected')
            original = self._session_file.read_bytes() if self._session_file.exists() else None
            self._session_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            staging = Path(tempfile.mkdtemp(prefix='.proton-job-', dir=str(self._session_file.parent)))
            staged_session = staging / 'session.json'
            try:
                if original is not None:
                    secure_write_file(staged_session, original.decode())
                request = dict(operation=operation, endpoint=endpoint, method=method, data=data,
                               session_file=str(staged_session), username=self._user, password=self._pass,
                               client_version=self.config.get('PROTON_CLIENT_VERSION', PROTON_CLIENT_VERSION))
                env = dict(os.environ)
                gnupg_home = staging / 'gnupg'
                gnupg_home.mkdir(mode=0o700)
                secure_write_file(gnupg_home / 'gpg.conf', 'no-autostart\n')
                env['GNUPGHOME'] = str(gnupg_home)
                package_root = str(Path(__file__).resolve().parents[2])
                env['PYTHONPATH'] = package_root + os.pathsep + env.get('PYTHONPATH', '')
                result = await async_run_command(
                    [sys.executable, '-m', 'mole_pkg.providers.proton_worker'],
                    120 if operation == 'authenticate' else 45, env=env,
                    input_data=json.dumps(request).encode())
                if result.returncode != 0:
                    raise SDKFailure('local_state')
                reply = json.loads(result.stdout)
                if not isinstance(reply, dict):
                    raise SDKFailure('invalid_response')
                if reply.get('error'):
                    raise SDKFailure(reply['error'])
                if not isinstance(reply.get('result'), dict):
                    raise SDKFailure('invalid_response')
                current = self._session_file.read_bytes() if self._session_file.exists() else None
                if generation != self.state.generation or current != original:
                    raise RuntimeError('stale Proton operation rejected')
                session_data = json.loads(staged_session.read_text())
                if not isinstance(session_data, dict):
                    raise RuntimeError('invalid staged Proton session')
                os.chmod(staged_session, 0o600)
                os.replace(staged_session, self._session_file)
                return reply['result']
            except asyncio.TimeoutError:
                raise SDKFailure('local_state' if operation == 'load' else 'transient') from None
            except (ValueError, TypeError, KeyError):
                raise SDKFailure('invalid_response') from None
            except OSError:
                raise SDKFailure('local_state') from None
            finally:
                shutil.rmtree(staging)

    async def _api_request(self, endpoint, method='GET', data=None):
        return await self._run_sdk_job('api', endpoint, method, data)

    @property
    def failover_enabled(self):
        return self.config.get('PROTON_FAILOVER_ENABLED', 'false').lower() in ('true', '1', 'yes', 'on')

    def _policy(self):
        if self._recovery_policy is None:
            # Reuse Config validation even when embedded callers provide only get().
            settings = Config('/nonexistent')
            settings._data = {key: self.config.get(key, default) for key, default in (
                ('PROTON_FAILOVER_ENABLED', 'false'), ('PROTON_FAILOVER_SERVERS', ''),
                ('PROTON_SERVER', ''), ('PROTON_FAILOVER_COOLDOWN', '900'),
                ('PROTON_FAILOVER_MAX_ATTEMPTS', '3'))}
            settings.validate_proton_failover()
            self._recovery_policy = ApprovedServerPolicy(settings.proton_failover_servers,
                self._server_name or '', settings.proton_failover_cooldown)
        return self._recovery_policy

    def record_server_failure(self, reason: str) -> None:
        if self.failover_enabled and self._selected_server:
            self._policy().failed(self._selected_server['entry_ip'], time.monotonic())

    def record_server_success(self) -> None:
        if self.failover_enabled and self._selected_server:
            self._policy().succeeded(self._selected_server['entry_ip'])

    def _select(self, server):
        self._selected_server = server
        if self.state.connected and self.state.tunnel_ready:
            return
        self.state.server_ip = server['entry_ip']
        self.state.server_hostname = server['hostname']
        self.state.server_country = server.get('country')

    async def restore_server(self, previous):
        if self.config.get('PROTON_RECOVERY_MODE', 'legacy') == 'validated':
            for candidate in getattr(self, '_validated_candidates', []):
                if candidate['name'] == previous['name'] and candidate['entry_ip'] == previous['entry_ip']:
                    self._select(candidate)
                    return True
            return False
        servers = await self._fetch_servers()
        if not servers:
            return False
        for candidate in self._filter_servers(servers):
            if candidate['name'] == previous['name'] and candidate['entry_ip'] == previous['entry_ip']:
                if self.failover_enabled and candidate['name'] not in self._policy().names:
                    return False
                self._select(candidate)
                return True
        return False

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
        try:
            result = await self._run_sdk_job('authenticate')
            if result.get('authenticated') is not True:
                return False
            self._proton_session = ProtonSessionWrapper(
                self._session_file, self.config.get('PROTON_CLIENT_VERSION', PROTON_CLIENT_VERSION))
            return True
        except RuntimeError:
            log.warning('Proton authentication failed; check session and client compatibility')
            return False

    def _local_discovery_binding(self) -> Tuple[str, str, Dict[str, Any]]:
        from ..discovery import _PrivateRecord, identity_scope
        session = _PrivateRecord(self._session_file)._read()
        certificate = _PrivateRecord(Path(self.config.state_dir) / 'proton_certificate.json')._read()
        if (not isinstance(session, dict) or session.get('api_url') != PROTON_API_URL or
                not isinstance(session.get('session_data'), dict) or not isinstance(certificate, dict)):
            raise ValueError('missing local discovery binding')
        saved = session['session_data']
        for name in ('UID', 'AccessToken', 'RefreshToken'):
            if not isinstance(saved.get(name), str) or not saved[name]:
                raise ValueError('incomplete local session')
        for name in ('x25519_private_key', 'ed25519_public_key'):
            value = certificate.get(name)
            if not isinstance(value, str) or len(base64.b64decode(value, validate=True)) != 32:
                raise ValueError('invalid saved certificate identity')
        expiration = certificate.get('expiration_time')
        if (not isinstance(expiration, (int, float)) or isinstance(expiration, bool) or
                not time.time() + 3600 < expiration < float('inf')):
            raise ValueError('saved certificate requires online renewal')
        return identity_scope(PROTON_API_URL, saved['UID'], self._user, self._tier,
                              certificate['ed25519_public_key']), saved['UID'], certificate

    async def _revalidate_saved_certificate(self, certificate: Dict[str, Any]):
        request = dict(ClientPublicKey=certificate['ed25519_public_key'], DeviceName='mole',
                       Mode='persistent', Features=dict(SafeMode=False, SplitTCP=False,
                       PortForwarding=self.config.port_forward, NetShieldLevel=self._netshield_level,
                       RandomNAT=False))
        response = await self._api_request('/vpn/v1/certificate', 'POST', request)
        expiry = response.get('ExpirationTime')
        if (response.get('Code') != 1000 or not isinstance(expiry, (int, float)) or isinstance(expiry, bool) or
                not time.time() + 3600 < expiry < float('inf')):
            raise SDKFailure('invalid_response')
        self._save_certificate(certificate['x25519_private_key'], certificate['ed25519_public_key'], expiry, 'mole')

    async def prepare_recovery(self):
        try:
            return await self._prepare_recovery(allow_refresh=True)
        finally:
            self._active_preparation_pending = None

    @staticmethod
    def candidate_identity(candidate):
        return tuple(candidate.get(name) for name in ('name', 'entry_ip', 'port', 'public_key'))

    def authorization_current(self, candidate):
        from ..discovery import RejectionJournal
        try:
            scope, _, _ = self._local_discovery_binding()
            if scope != self._validated_scope or time.monotonic() >= self._validated_deadline:
                return False
            if not any(self.candidate_identity(c) == self.candidate_identity(candidate)
                       for c in self._validated_candidates):
                return False
            marker = RejectionJournal(Path(self.config.state_dir) / 'discovery_blocked.json')._checked()
            if marker is not None and not (marker['kind'] == 'pending' and
                    self._active_preparation_pending == (marker['scope'], marker['transaction_id']) and
                    marker['scope'] == scope):
                return False
            return True
        except (OSError, ValueError, TypeError, KeyError):
            return False

    async def _publish_recovery_context(self, candidates, scope: Optional[str], age: float = 0, record=None):
        if self.before_recovery_change is not None:
            await self.before_recovery_change(candidates, scope)
        if record is not None:
            from ..discovery import DiscoveryCache
            DiscoveryCache(Path(self.config.state_dir) / 'proton_discovery.json').publish(record)
        self._validated_candidates = list(candidates)
        self._validated_scope = scope
        self._validated_deadline = (time.monotonic() + max(0,
            (self.config.proton_discovery_max_age or 86400) - age)) if scope else 0

    async def _prepare_recovery(self, allow_refresh):
        """Warm live discovery, or reuse a complete scoped record on transient failure."""
        from ..discovery import DiscoveryCache, RejectionJournal, normalize_candidates
        directory = Path(self.config.state_dir)
        cache = DiscoveryCache(directory / 'proton_discovery.json')
        journal = RejectionJournal(directory / 'discovery_blocked.json')
        # An incomplete local identity cannot enable fallback. Its provisional
        # barrier still precedes any authentication/certificate network request.
        provisional = hashlib.sha256((PROTON_API_URL + '\0' + self._user + '\0' + str(self._tier)).encode()).hexdigest()
        scope, uid, certificate = provisional, None, None
        transaction, created = None, False
        prior_record = None
        try:
            try:
                scope, uid, certificate = self._local_discovery_binding()
            except (OSError, ValueError, TypeError, KeyError):
                pass
            if uid is not None:
                prior_record = cache.load(scope, time.time(), time.monotonic(),
                    Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 86400)
            blocked_before = journal.blocked(scope)
            transaction, created = journal.begin(scope, time.time())
            self._active_preparation_pending = (scope, transaction) if created else None
            if uid is None:
                # Missing local material requires an online setup, never a cache shortcut.
                result = await self._run_sdk_job('authenticate')
                if result.get('authenticated') is not True:
                    raise SDKFailure('credentials_rejected')
                private, public = await self._generate_wireguard_keys()
                certificate = dict(x25519_private_key=private, ed25519_public_key=public)
                await self._revalidate_saved_certificate(certificate)
                scope, uid, certificate = self._local_discovery_binding()
            loaded = await self._run_sdk_job('load')
            if loaded.get('uid') != uid:
                raise SDKFailure('local_state')
            self._proton_session = ProtonSessionWrapper(self._session_file, self.config.proton_client_version)
            entitlement = await self._api_request('/vpn/v2')
            entitlement_time = time.time()
            maximum = entitlement.get('VPN', {}).get('MaxTier')
            if entitlement.get('Code') != 1000 or type(maximum) is not int or not 0 <= maximum <= 2:
                raise SDKFailure('invalid_response')
            self._effective_tier = min(self._tier, maximum)
            response = await self._api_request('/vpn/logicals')
            if response.get('Code') != 1000:
                raise SDKFailure('invalid_response')
            candidates = normalize_candidates(response.get('LogicalServers'), self._policy().names,
                self._effective_tier, self.config.port_forward or self._prefer_p2p)
            if blocked_before:
                if certificate is None:
                    raise SDKFailure('local_state')
                await self._revalidate_saved_certificate(certificate)
            current_scope, current_uid, _ = self._local_discovery_binding()
            if (current_scope, current_uid) != (scope, uid):
                raise SDKFailure('local_state')
            record: Dict[str, Any] = dict(schema=1, scope=scope, entitlement_tier=self._effective_tier,
                          entitlement_observed_wall=entitlement_time, observed_wall=time.time(),
                          boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                          observed_mono=time.monotonic(), candidates=candidates)
            await self._publish_recovery_context(candidates, scope,
                max(0, record['observed_wall'] - entitlement_time), record=record)
            journal.finish(scope, transaction, 'success', created, revalidated=True)
            self.state.discovery_source = 'live'
            self.state.recovery_reason = 'none'
            self.state.cache_age_seconds = None
            return True
        except SDKFailure as error:
            restricted = (prior_record is not None and getattr(self, '_effective_tier', 2) <
                          prior_record['entitlement_tier'])
            if error.kind != 'transient' or restricted:
                await self._publish_recovery_context([], None)
            if transaction is not None and not (error.kind == 'transient' and restricted):
                journal.finish(scope, transaction, error.kind, created)
            if error.kind == 'credentials_rejected' and allow_refresh:
                # One refresh-only online revalidation, never a password loop.
                # Rejection remains durable until the entire subsequent warmup succeeds.
                try:
                    refreshed = await self._run_sdk_job('refresh')
                    if refreshed.get('authenticated') is True:
                        return await self._prepare_recovery(allow_refresh=False)
                except SDKFailure:
                    pass
            if error.kind == 'transient' and uid is not None and not journal.blocked(scope):
                value = cache.load(scope, time.time(), time.monotonic(),
                    Path('/proc/sys/kernel/random/boot_id').read_text().strip(), self.config.proton_discovery_max_age)
                if value is not None and value['entitlement_tier'] <= self._tier:
                    # A freshly observed restriction must not be forgotten on
                    # an immediately following discovery timeout.
                    if getattr(self, '_effective_tier', value['entitlement_tier']) < value['entitlement_tier']:
                        return False
                    self._effective_tier = value['entitlement_tier']
                    candidates = [c for c in value['candidates']
                        if c['name'] in self._policy().names and c['tier'] <= self._effective_tier and
                        (not (self.config.port_forward or self._prefer_p2p) or c['features'] & 4)]
                    await self._publish_recovery_context(candidates, scope, value['cache_age_seconds'])
                    self.state.discovery_source = 'cache'
                    self.state.recovery_reason = 'none'
                    self.state.cache_age_seconds = value['cache_age_seconds']
                    self.state.cache_age_recorded_mono = time.monotonic()
                    self._proton_session = ProtonSessionWrapper(self._session_file, self.config.proton_client_version)
                    return True
            self.state.recovery_reason = {'credentials_rejected': 'credentials_rejected',
                'compatibility': 'compatibility_rejected', 'transient': 'transient_discovery'}.get(
                    error.kind, 'authorization_unknown')
            await self._publish_recovery_context([], None)
            self.state.discovery_source = 'none'
            return False
        except (OSError, ValueError, TypeError, KeyError):
            # Unknown/persistence/malformed completion leaves the durable barrier.
            self.state.recovery_reason = 'authorization_unknown'
            await self._publish_recovery_context([], None)
            self.state.discovery_source = 'none'
            return False

    async def _fetch_servers(self) -> Optional[List[Dict]]:
        """Fetch server list from ProtonVPN API"""
        if not self._proton_session and not self._session_file.exists():
            log.error("Not authenticated")
            return None

        try:
            log.info("Fetching server list...")
            response = await self._api_request("/vpn/logicals")

            if response.get("Code") != 1000:
                log.error('Failed to fetch Proton servers')
                return None

            servers = response.get("LogicalServers", [])
            log.info(f"Found {len(servers)} servers")
            return servers

        except Exception:
            log.error('Failed to fetch Proton servers')
            return None

    def _filter_servers(self, servers: List[Dict], country: Optional[str] = None) -> List[Dict]:
        """Filter servers based on user preferences.

        Args:
            servers: Raw server list from API
            country: Optional country code to filter by (for fallback support)
        """
        if self.config.get('PROTON_RECOVERY_MODE', 'legacy') == 'validated':
            from ..discovery import normalize_candidates
            return normalize_candidates(servers, self._policy().names,
                                        getattr(self, '_effective_tier', self._tier),
                                        self.config.port_forward or self._prefer_p2p)
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
                if s.get('Status') == 0:
                    continue
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

    async def _ping_server(self, server: Dict) -> Optional[float]:
        """Ping a server and return latency in ms, or None if unreachable"""
        try:
            result = await async_run_command(
                ["ping", "-c", "1", "-W", "2", server["entry_ip"]],
                timeout=3
            )
            if result.returncode == 0:
                for part in result.stdout.split():
                    if part.startswith("time="):
                        return float(part[5:])
        except Exception:
            pass
        return None

    async def _filter_by_latency(self, servers: List[Dict]) -> List[Dict]:
        """Filter and sort servers by latency if PROTON_MAX_LATENCY is set"""
        max_latency = self._max_latency
        if max_latency <= 0 and len(servers) <= 5:
            # No latency filtering, just return sorted by load
            return servers

        log.info(f"Testing latency for {min(len(servers), 20)} servers...")

        # Test up to 20 servers in parallel
        test_servers = servers[:20]
        results = []

        semaphore = asyncio.Semaphore(10)

        async def probe(server):
            async with semaphore:
                return server, await self._ping_server(server)

        for server, latency in await asyncio.gather(*(probe(s) for s in test_servers)):
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
        if self.config.get('PROTON_RECOVERY_MODE', 'legacy') == 'validated':
            candidates = self._policy().candidates(getattr(self, '_validated_candidates', []), time.monotonic())
            if not candidates:
                return False
            self._select(candidates[0])
            return True
        servers = await self._fetch_servers()
        if not servers:
            return False

        if self.failover_enabled:
            candidates = self._policy().candidates(self._filter_servers(servers), time.monotonic())
            if not candidates:
                log.warning('No approved Proton endpoint is outside cooldown')
                return False
            self._select(candidates[0])
            return True

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
                        self._select(server)
                        log.info(f"Server: {server['name']} ({server['entry_ip']})")
                        return True

                if using_saved_server:
                    log.info(f"Last server '{target_name}' not available, selecting new server...")
                    target_name = None
                    using_saved_server = False
                else:
                    # A strict pin may belong to a later configured country.
                    continue

            # Apply latency filtering if configured or many servers
            if self._max_latency > 0 or len(filtered) > 5:
                filtered = await self._filter_by_latency(filtered)
            else:
                # Sort by load (lower is better)
                filtered.sort(key=lambda s: s["load"])

            if filtered:
                server = filtered[0]
                self._select(server)
                log.info(f"Server: {server['name']} ({server['entry_ip']}) - {server['load']}% load")
                return True

        # All countries exhausted
        log.error("No suitable servers found matching criteria")
        if self._countries:
            log.error(f"  Countries tried: {', '.join(self._countries)}")
        if self.config.port_forward:
            log.error("  Port forwarding requires P2P servers (Plus plan)")
        return False

    async def _generate_wireguard_keys(self) -> tuple:
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
        key_response = await self._api_request("/vpn/v1/certificate/key/EC")

        if key_response.get('Code') != 1000:
            raise RuntimeError('Proton key generation failed')

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
                          expiration_time: float, device_name: str) -> None:
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

        server = self._selected_server.copy()
        generation = self.state.generation

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
                x25519_private_key, ed25519_public_key = await self._generate_wireguard_keys()

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

                response = await self._api_request(
                    "/vpn/v1/certificate",
                    "POST",
                    cert_request
                )

                if response.get("Code") != 1000:
                    log.error('Proton certificate registration failed')
                    return False

                if generation != self.state.generation or self._selected_server != server:
                    return False

                # Save certificate for future use
                expiration_time = response.get("ExpirationTime", 0)
                self._save_certificate(x25519_private_key, ed25519_public_key,
                                       expiration_time, device_name)

                log.info(f"New certificate registered (expires {datetime.fromtimestamp(expiration_time)})")

            except Exception:
                log.error('Proton WireGuard registration failed')
                return False

        # Configure WireGuard with the certificate
        try:
            if generation != self.state.generation or self._selected_server != server:
                return False
            # Proton assigns addresses in 10.2.0.0/16 range
            peer_ip = "10.2.0.2"
            if not self.state.tunnel_ready:
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
            config_path = Path(self.config.wg_conf)
            temporary = config_path.with_name(config_path.name + '.pending')
            secure_write_file(temporary, wg_config)
            os.replace(temporary, config_path)

            # Save state
            state_dir = Path(self.config.state_dir)
            state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not self.state.tunnel_ready:
                secure_write_file(state_dir / "server_ip", server['entry_ip'])
                secure_write_file(state_dir / "hostname", server['hostname'])
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
        result = await async_run_command(["which", "natpmpc"], timeout=10)
        if result.returncode != 0:
            log.error("natpmpc not installed. Install with: apt install natpmpc")
            return False

        return await self._renew_port_mappings()

    async def _request_port_mapping(self, protocol: str):
        started = time.monotonic()
        result = await async_run_in_netns([
            "natpmpc", "-a", "1", "0", protocol, "60", "-g", self._natpmp_gateway
        ], self.config.netns, timeout=10)
        if result.returncode != 0:
            log.warning(f"NAT-PMP {protocol.upper()} request failed")
            return None

        match = re.search(
            r"^Mapped public port (\d+) protocol " + protocol.upper()
            + r" to local port \d+ lifetime (\d+)\s*$",
            result.stdout, re.MULTILINE,
        )
        if not match:
            log.warning(f"Invalid NAT-PMP {protocol.upper()} mapping response")
            return None
        port, lifetime = map(int, match.groups())
        if not 1 <= port <= 65535 or lifetime <= 0:
            log.warning(f"Invalid NAT-PMP {protocol.upper()} port or lifetime")
            return None
        return port, started + lifetime

    def forwarding_valid(self) -> bool:
        valid = bool(self.state.port and self.state.port_deadline > time.monotonic())
        self.state.forwarding_ready = valid
        return valid

    def port_refresh_delay(self, configured: float) -> float:
        remaining = self.state.port_deadline - time.monotonic()
        if remaining <= 0:
            self.state.forwarding_ready = False
            return min(configured, 5)
        return min(configured, 45, max(.1, remaining / 2))

    async def _renew_port_mappings(self) -> bool:
        generation = self.state.generation
        if self._mapping_lock is None:
            self._mapping_lock = asyncio.Lock()
        async with self._mapping_lock:
            if generation != self.state.generation:
                return False
            return await self._renew_locked(generation)

    async def _renew_locked(self, generation: int) -> bool:
        try:
            udp = await self._request_port_mapping("udp")
            if udp is None:
                return False
            tcp = await self._request_port_mapping("tcp")
            if tcp is None:
                return False

            deadline = min(udp[1], tcp[1])
            if generation != self.state.generation or deadline <= time.monotonic():
                return False
            if udp[0] != tcp[0]:
                log.warning(f"NAT-PMP protocol port mismatch: UDP={udp[0]}, TCP={tcp[0]}")
                return False

            # Proton may assign a new port after a lease expires, even without reconnecting.
            port = udp[0]
            previous_port = self.state.port or self._load_saved_port()
            secure_write_file(Path(self.config.state_dir) / "port", str(port))
            self.state.port = port
            if previous_port != port:
                self.state.client_ready = False
            self.state.port_deadline = deadline
            self.state.port_expires = datetime.now() + timedelta(seconds=deadline - time.monotonic())
            self.state.forwarding_ready = True
            if previous_port != port:
                log.info(f"NAT-PMP forwarded port changed: {previous_port} -> {port}")
            return True
        except Exception:
            self.forwarding_valid()
            log.warning("NAT-PMP mapping renewal failed or timed out")
            return False

    async def refresh_port_forward(self) -> bool:
        """Refresh NAT-PMP port mapping (must be called every ~45 seconds)"""
        if not self.config.port_forward:
            return True

        self.forwarding_valid()
        return await self._renew_port_mappings()
