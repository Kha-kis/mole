import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from mole_pkg.config import Config
from mole_pkg.mole import Mole
from mole_pkg.network import ValidationGate
from mole_pkg.providers.proton import ProtonProvider
from mole_pkg.utils import VPNState, _process_identity
from mole_pkg.validation import Attempt, ValidationRound
from test_validation import candidate


class ValidatedLifecycle(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.mole = Mole.__new__(Mole)
        self.mole.config = Config('/nonexistent')
        self.mole.config._data.update(PROTON_RECOVERY_MODE='validated', STATE_DIR=self.root.name,
                                      PORT_FORWARD='false', TORRENT_CLIENT='none')
        self.mole.state = VPNState(generation=2)
        self.mole.shutdown_event = asyncio.Event()
        self.mole.torrent = None
        self.attempt = Attempt(_process_identity(os.getpid()), 2, 'a' * 64, candidate(), 'b' * 64,
                               time.monotonic() + 90)
        self.mole._validation_attempt = self.attempt
        self.mole.provider = type('Provider', (), {'authorization_current': lambda self, candidate: True})()
        self.calls = []
        self.gate = self.mole._validation_gate = ValidationGate('qa-fixture', '10.200.200.1/32')
        self.gate.attempt = self.attempt

        async def prepare(value):
            self.calls.append('fence')
            return ValidationRound('c' * 64, value, time.monotonic())

        async def authorize(*args, current_check=None):
            if current_check is not None and not current_check():
                raise RuntimeError('invalidated fixture')
            self.calls.append('authorize')
            self.gate.deadline = time.monotonic() + 80

        self.gate.prepare_round = AsyncMock(side_effect=prepare)
        self.gate.authorize = AsyncMock(side_effect=authorize)
        self.gate.verify_open = AsyncMock(return_value=True)
        self.gate.revoke = AsyncMock(side_effect=lambda *args: self.calls.append('revoke'))
        self.mole._validator = type('Validator', (), {})()
        self.mole._validator.describe = AsyncMock(return_value='b' * 64)

        async def validate(value, round_, probe, deadline):
            self.calls.append('observe')
            return dict(attempt=value.to_dict(), round_id=round_.id, allowed=True,
                        authorization_deadline=time.monotonic() + 120,
                        transport_deadline=time.monotonic() + 120)

        self.mole._validator.validate = AsyncMock(side_effect=validate)

    async def test_fence_then_fresh_observation_then_authorize_before_ready(self):
        self.assertTrue(await self.mole._validate_current_attempt())
        self.assertEqual(self.calls, ['fence', 'observe', 'authorize'])
        self.assertTrue(self.mole.state.authorization_ready)
        self.assertTrue(self.mole.state.gate_open)
        self.assertTrue(self.mole.state.tunnel_ready)

    async def test_policy_change_closes_before_probe(self):
        self.mole._validator.describe.return_value = 'd' * 64
        self.assertFalse(await self.mole._validate_current_attempt())
        self.assertEqual(self.calls, ['revoke'])
        self.assertFalse(self.mole.state.gate_open)

    async def test_generation_change_during_probe_cannot_grant(self):
        async def changed(value, round_, probe, deadline):
            self.mole.state.generation += 1
            return dict(attempt=value.to_dict(), round_id=round_.id, allowed=True,
                        authorization_deadline=time.monotonic() + 120,
                        transport_deadline=time.monotonic() + 120)
        self.mole._validator.validate.side_effect = changed
        self.assertFalse(await self.mole._validate_current_attempt())
        self.assertNotIn('authorize', self.calls)
        self.assertIn('revoke', self.calls)

    async def test_cancelled_validation_revokes_without_client_restart(self):
        self.mole._validator.validate.side_effect = asyncio.CancelledError
        self.mole._restart_torrent_service = AsyncMock()
        with self.assertRaises(asyncio.CancelledError):
            await self.mole._validate_current_attempt()
        self.assertEqual(self.calls, ['fence', 'revoke'])
        self.mole._restart_torrent_service.assert_not_awaited()

    async def test_dns_failure_is_repaired_locally_without_rotating_peer(self):
        self.mole.state.authorization_ready = self.mole.state.gate_open = True
        self.mole.state.authorization_deadline = time.monotonic() + 90
        self.mole._probe_dns = AsyncMock(side_effect=[False, True])
        self.mole._repair_dns_worker = AsyncMock(return_value=True)
        self.mole._full_renewal = AsyncMock()
        self.assertTrue(await self.mole._check_dns_health())
        self.assertTrue(self.mole.state.dns_ready)
        self.mole._repair_dns_worker.assert_awaited_once()
        self.mole._full_renewal.assert_not_awaited()

    async def test_quarantine_dns_failure_does_not_restart_any_worker(self):
        self.mole.state.authorization_ready = self.mole.state.gate_open = False
        self.mole._probe_dns = AsyncMock(return_value=False)
        self.mole._repair_dns_worker = AsyncMock()
        self.assertFalse(await self.mole._check_dns_health())
        self.mole._repair_dns_worker.assert_not_awaited()

    async def test_failed_revoke_invalidates_status_and_attempts_interface_down(self):
        self.mole.state.authorization_ready = self.mole.state.gate_open = True
        self.gate.revoke.side_effect = RuntimeError('fixture')
        with patch('mole_pkg.mole.async_disconnect_vpn', new=AsyncMock()) as down:
            with self.assertRaises(RuntimeError):
                await self.mole._stop_validation()
        self.assertFalse(self.mole.state.gate_open)
        self.assertFalse(self.mole.state.authorization_ready)
        down.assert_awaited_once()

    async def test_withdrawn_candidate_cannot_refresh_an_existing_gate(self):
        self.mole.provider.authorization_current = lambda candidate: False
        self.assertFalse(await self.mole._validate_current_attempt())
        self.assertNotIn('authorize', self.calls)
        self.assertEqual(self.calls, ['revoke'])

    async def test_authoritative_withdrawal_closes_old_tunnel_instead_of_renewal_success(self):
        self.mole.config._data.update(VPN_PROVIDER='proton', PROTON_FAILOVER_ENABLED='true',
                                      PROTON_FAILOVER_SERVERS='NL#1')
        provider = self.mole.provider = ProtonProvider(self.mole.config, self.mole.state)
        provider._validated_candidates = [candidate()]
        provider._selected_server = candidate()
        provider.authorization_current = lambda value: value in provider._validated_candidates
        self.mole.state.connected = self.mole.state.tunnel_ready = True
        self.mole.state.authorization_ready = self.mole.state.gate_open = True
        async def withdraw():
            provider._validated_candidates = []
            return True
        provider.prepare_recovery = AsyncMock(side_effect=withdraw)
        self.assertFalse(await self.mole._full_renewal())
        self.assertFalse(self.mole.state.gate_open)
        self.assertIn('revoke', self.calls)

    async def test_known_rejection_revokes_even_when_preparation_returns_false(self):
        provider = self.mole.provider
        async def reject():
            provider.authorization_current = lambda value: False
            self.mole.state.recovery_reason = 'compatibility_rejected'
            return False
        provider.prepare_recovery = AsyncMock(side_effect=reject)
        self.mole.state.gate_open = self.mole.state.authorization_ready = True
        self.mole._defer_recovery = lambda: None
        self.assertFalse(await self.mole._full_renewal())
        self.assertFalse(self.mole.state.gate_open)
        self.assertIn('revoke', self.calls)

    async def test_validated_health_retries_client_and_listener_without_forwarding(self):
        self.mole.torrent = object()
        self.mole.state.client_ready = False
        self.mole.state.port = 12345
        self.mole._start_torrent_sync = Mock()
        self.mole._check_torrent_listener = AsyncMock()
        self.assertTrue(await self.mole._check_health())
        await asyncio.sleep(0)
        self.mole._start_torrent_sync.assert_called_once()
        self.mole._check_torrent_listener.assert_awaited_once()

    async def test_repair_kills_download_group_after_dns_parent_already_exited(self):
        import subprocess
        import sys
        program = ('import subprocess,sys; p=subprocess.Popen([sys.executable,"-c",'
                   '"import time;time.sleep(60)"],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,'
                   'stderr=subprocess.DEVNULL);print(p.pid,flush=True)')
        parent = subprocess.Popen([sys.executable, '-c', program], stdout=subprocess.PIPE,
                                  text=True, start_new_session=True)
        try:
            child = int(parent.stdout.readline())
            self.mole._dns_proc_identity = _process_identity(parent.pid)
            parent.wait(timeout=2)
            self.mole._dns_proc = parent
            self.mole.config._data['DOT_ENABLED'] = 'true'
            self.mole._configured_resolvers = lambda: ['127.0.0.1']
            self.mole._probe_dns = AsyncMock(return_value=True)
            class FreshWorker:
                def poll(self):
                    return None
            self.mole._start_dns_server = lambda **kwargs: setattr(self.mole, '_dns_proc', FreshWorker())
            self.assertTrue(await self.mole._repair_dns_worker())
            for _ in range(20):
                try:
                    state = Path('/proc/{}/stat'.format(child)).read_text().rpartition(')')[2].split()[0]
                except FileNotFoundError:
                    break
                if state == 'Z':
                    break
                await asyncio.sleep(.01)
            else:
                self.fail('old DNS download descendant remains running')
        finally:
            import signal
            try:
                os.killpg(parent.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            parent.wait(timeout=2)
            parent.stdout.close()

    async def test_scheduling_preserves_the_known_component_failure(self):
        self.mole.config._data.update(VPN_PROVIDER='proton', PROTON_FAILOVER_ENABLED='true',
                                      PROTON_FAILOVER_SERVERS='NL#1')
        self.mole.provider = ProtonProvider(self.mole.config, self.mole.state)
        self.mole.state.recovery_reason = 'compatibility_rejected'
        self.mole._defer_recovery()
        self.assertEqual(self.mole.state.recovery_reason, 'compatibility_rejected')
        self.assertGreater(self.mole._recovery_not_before, time.monotonic())

    async def test_explicit_denial_is_not_reported_as_unknown(self):
        from mole_pkg.validation import AuthorizationDenied
        self.mole._validator.validate.side_effect = AuthorizationDenied('denied')
        self.assertFalse(await self.mole._validate_current_attempt())
        self.assertEqual(self.mole.state.recovery_reason, 'authorization_denied')

    async def test_remaining_cycle_budget_is_shared_without_monopolizing_later_candidates(self):
        from types import SimpleNamespace
        from datetime import datetime
        self.mole.config._data.update(VPN_PROVIDER='proton', PROTON_FAILOVER_ENABLED='true',
                                      PROTON_FAILOVER_SERVERS='NL#1')
        provider = self.mole.provider = ProtonProvider(self.mole.config, self.mole.state)
        clock = SimpleNamespace(now=1000.0)
        budgets = []
        servers = [dict(candidate(), entry_ip=ip) for ip in ('1.1.1.1', '8.8.8.8', '9.9.9.9')]
        async def select():
            if len(budgets) == 3:
                return False
            provider._selected_server = servers[len(budgets)]
            return True
        async def exhausted(old):
            budgets.append(self.mole._candidate_deadline - clock.now)
            clock.now = self.mole._candidate_deadline
            return False
        provider.get_server = AsyncMock(side_effect=select)
        provider.record_server_failure = Mock()
        self.mole._attempt_selected_server = exhausted
        self.mole._cycle_deadline = 1120.0
        # Replace only Mole's clock reference; never freeze asyncio's clock.
        with patch('mole_pkg.mole.time', SimpleNamespace(monotonic=lambda: clock.now,
                                                       time=lambda: datetime.now().timestamp())):
            self.assertFalse(await self.mole._recover_candidates('readiness'))
        self.assertEqual(budgets, [40, 40, 40])
