import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from mole_pkg.config import Config
from mole_pkg.mole import Mole
from mole_pkg.network import ValidationGate
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
        self.calls = []
        self.gate = self.mole._validation_gate = ValidationGate('qa-fixture', '10.200.200.0/24')
        self.gate.attempt = self.attempt

        async def prepare(value):
            self.calls.append('fence')
            return ValidationRound('c' * 64, value, time.monotonic())

        async def authorize(*args):
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
