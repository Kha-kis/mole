import asyncio
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

from mole_pkg.config import Config
from mole_pkg.mole import Mole
from mole_pkg.providers.proton import ProtonProvider
from mole_pkg.utils import VPNState
from test_recovery_policy import server


class RecoveryOrchestration(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.config = Config('/nonexistent')
        self.config._data.update(STATE_DIR=self.root.name, PROTON_FAILOVER_ENABLED='true',
                                 PROTON_FAILOVER_SERVERS='XX#1,XX#2,XX#3', PROTON_SERVER='XX#1',
                                 PORT_FORWARD='false', TORRENT_CLIENT='none')
        self.mole = Mole.__new__(Mole)
        self.mole.config = self.config
        self.mole.state = VPNState()
        self.mole.provider = ProtonProvider(self.config, self.mole.state)
        self.mole.torrent = None
        self.mole.shutdown_event = asyncio.Event()
        self.mole._torrent_update_lock = None
        self.mole._torrent_sync_task = None
        self.mole._run_hook = Mock(return_value=True)
        self.servers = [server('XX#1', '192.0.2.1'), server('XX#2', '192.0.2.2'), server('XX#3', '192.0.2.3')]
        self.mole.provider._fetch_servers = AsyncMock(return_value=self.servers)
        self.mole.provider._filter_servers = lambda values, country=None: values
        self.mole.provider.authenticate = AsyncMock(return_value=True)
        self.mole.provider.register_wireguard = AsyncMock(return_value=True)
        self.mole.provider.setup_port_forward = AsyncMock(return_value=True)
        self.attempts = []
        self.healthy = {'192.0.2.1', '192.0.2.2', '192.0.2.3'}

        async def connect(old):
            address = self.mole.state.server_ip
            self.attempts.append(address)
            self.mole.state.generation += 1
            self.mole.state.connected = self.mole.state.tunnel_ready = address in self.healthy
            self.mole.state.tunnel_deadline = time.monotonic() + 90
            return self.mole.state.connected

        self.mole._connect_vpn = AsyncMock(side_effect=connect)

    async def test_overlapping_triggers_share_one_renewal(self):
        async def authenticate():
            await asyncio.sleep(.02)
            return True
        self.mole.provider.authenticate.side_effect = authenticate
        results = await asyncio.gather(self.mole._full_renewal(), self.mole._full_renewal(), self.mole._full_renewal())
        self.assertEqual(results, [True] * 3)
        self.assertEqual(self.mole.provider.authenticate.await_count, 1)
        self.assertEqual(self.attempts, ['192.0.2.1'])

    async def test_first_failed_endpoint_moves_to_approved_second(self):
        self.healthy.remove('192.0.2.1')
        self.assertTrue(await self.mole._full_renewal())
        self.assertEqual(self.attempts, ['192.0.2.1', '192.0.2.2'])

    async def test_exhaustion_is_blocked_bounded_and_backed_off(self):
        self.healthy.clear()
        self.assertFalse(await self.mole._full_renewal())
        self.assertEqual(len(set(self.attempts)), 3)
        before = self.mole.provider.authenticate.await_count
        self.assertFalse(await self.mole._full_renewal())
        self.assertEqual(self.mole.provider.authenticate.await_count, before)
        self.assertFalse(self.mole.state.connected)
        self.assertGreaterEqual(self.mole._recovery_not_before - time.monotonic(), 29)
        self.assertLessEqual(self.mole._recovery_not_before - time.monotonic(), 300)

    async def test_mapping_failure_retains_verified_tunnel(self):
        self.config._data['PORT_FORWARD'] = 'true'
        self.mole.provider.setup_port_forward.return_value = False
        self.assertTrue(await self.mole._full_renewal())
        self.assertTrue(self.mole.state.connected)
        self.assertFalse(self.mole.state.forwarding_ready)
        self.assertEqual(self.attempts, ['192.0.2.1'])

    async def test_three_mapping_failures_allow_one_recovery_until_valid_lease(self):
        self.assertTrue(callable(getattr(self.mole, '_mapping_result', None)))
        self.assertFalse(self.mole._mapping_result(False))
        self.assertFalse(self.mole._mapping_result(False))
        self.assertTrue(self.mole._mapping_result(False))
        self.mole._mapping_recovered = True
        self.assertFalse(self.mole._mapping_result(False))
        self.mole._mapping_result(True)
        self.assertFalse(self.mole._mapping_result(False))
        self.assertEqual(self.mole._mapping_failures, 1)

    async def test_mapping_recovery_restores_previous_healthy_endpoint_once(self):
        self.config._data['PORT_FORWARD'] = 'true'
        self.mole.provider.setup_port_forward.return_value = False
        self.assertTrue(await self.mole._full_renewal())
        self.attempts.clear()
        self.healthy = {'192.0.2.1'}
        self.assertTrue(await self.mole._full_renewal(reason='mapping'))
        self.assertEqual(self.attempts, ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.1'])
        self.assertTrue(self.mole.state.connected)
        self.assertFalse(self.mole.state.forwarding_ready)
        self.assertEqual(self.mole.state.server_ip, '192.0.2.1')

    async def test_failed_restore_is_blocked_not_degraded(self):
        self.config._data['PORT_FORWARD'] = 'true'
        self.mole.provider.setup_port_forward.return_value = False
        self.assertTrue(await self.mole._full_renewal())
        self.healthy.clear()
        self.assertFalse(await self.mole._full_renewal(reason='mapping'))
        self.assertFalse(self.mole.state.connected)

    async def test_cancelled_waiter_does_not_cancel_owner(self):
        started, finish = asyncio.Event(), asyncio.Event()

        async def authenticate():
            started.set()
            await finish.wait()
            return True

        self.mole.provider.authenticate.side_effect = authenticate
        owner = asyncio.create_task(self.mole._full_renewal())
        await started.wait()
        waiter = asyncio.create_task(self.mole._full_renewal())
        await asyncio.sleep(0)
        waiter.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiter
        finish.set()
        self.assertTrue(await owner)
        self.assertEqual(self.mole.provider.authenticate.await_count, 1)

    async def test_cleanup_drains_recovery_before_disconnect(self):
        started, stopped = asyncio.Event(), asyncio.Event()

        async def worker():
            try:
                started.set()
                await asyncio.Event().wait()
            finally:
                stopped.set()

        self.mole._renewal_task = asyncio.create_task(worker())
        await started.wait()
        self.mole._keepalive_task = self.mole._watchdog_task = self.mole._restart_watcher_task = None
        self.mole._api_proc = self.mole._proxy_proc = self.mole._dns_proc = None
        try:
            with patch('mole_pkg.mole.disconnect_vpn', side_effect=lambda config: self.assertTrue(stopped.is_set())):
                await self.mole._cleanup()
        finally:
            self.mole._renewal_task.cancel()
            await asyncio.gather(self.mole._renewal_task, return_exceptions=True)

    async def test_registration_failure_cannot_relabel_old_tunnel_as_new_ready(self):
        self.assertTrue(await self.mole._full_renewal())
        self.mole.provider.register_wireguard.return_value = False
        self.assertFalse(await self.mole._full_renewal())
        self.assertFalse(self.mole.state.connected)
