import asyncio
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import test_recovery_orchestration as fixtures
from mole_pkg.config import validate_config
from mole_pkg.mole import Mole
from mole_pkg.services.api_main import HTTPAPIServerStandalone
from mole_pkg.utils import VPNState


def mole_fixture(directory, interval):
    mole = Mole.__new__(Mole)
    mole.config = Mock(port_forward=True, keepalive_interval=interval,
                       state_dir=directory, dot_enabled=False,
                       http_api_enabled=False, proxy_enabled=False)
    mole.state = VPNState(connected=True, port=12345, peer_ip='192.0.2.2')
    mole.shutdown_event = asyncio.Event()
    mole._torrent_update_lock = None
    mole._torrent_sync_task = None
    mole._keepalive_task = mole._watchdog_task = mole._restart_watcher_task = None
    return mole


class TestReviewRegressions(unittest.IsolatedAsyncioTestCase):
    async def test_inflight_old_port_is_reconciled_to_latest_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            mole = mole_fixture(directory, 0.02)
            release = asyncio.Event()
            captured, writes, renewals = [], [], []

            async def set_port(port):
                captured.append(port)
                if port == 22222:
                    await release.wait()
                writes.append(port)
                return True

            async def renew():
                renewals.append(True)
                if len(renewals) == 1:
                    mole.state.port = 22222
                else:
                    self.assertEqual(captured, [22222])
                    mole.state.port = 33333
                    release.set()
                    mole.shutdown_event.set()
                return True

            mole.torrent = Mock(set_interface=AsyncMock(return_value=True),
                                set_listen_port=AsyncMock(side_effect=set_port))
            mole.provider = Mock(refresh_port_forward=AsyncMock(side_effect=renew))
            with patch('mole_pkg.mole.increment_counter'
            ), patch('mole_pkg.mole.increment_dict_counter'), patch('mole_pkg.mole.atomic_write_state'):
                await asyncio.wait_for(mole._keepalive_loop(), timeout=1)
                await asyncio.wait_for(mole._torrent_sync_task, timeout=1)
            self.assertEqual(writes, [22222, 33333])

    async def test_late_success_does_not_mark_valid_leases_as_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            mole = mole_fixture(directory, 0.06)
            successes, renewals = [], []

            async def set_port(port):
                await asyncio.sleep(0.02)
                successes.append(port)
                return True

            async def renew():
                renewals.append(True)
                if len(renewals) == 3:
                    mole.shutdown_event.set()
                return True

            mole.torrent = Mock(set_interface=AsyncMock(return_value=True),
                                set_listen_port=AsyncMock(side_effect=set_port))
            mole.provider = Mock(refresh_port_forward=AsyncMock(side_effect=renew))
            with patch('mole_pkg.mole.increment_counter'
            ) as count, patch('mole_pkg.mole.increment_dict_counter'), patch('mole_pkg.mole.atomic_write_state'):
                await asyncio.wait_for(mole._keepalive_loop(), timeout=1)
                await mole._torrent_sync_task
            self.assertEqual(len(successes), 3)
            self.assertEqual([call.args[1] for call in count.call_args_list],
                             ['port_forward_renewals_success_total'] * 3)

    async def test_initial_client_wait_does_not_postpone_keepalive_start(self):
        with tempfile.TemporaryDirectory() as directory:
            mole = mole_fixture(directory, 0.01)
            mole.state.connected = False
            mole.state.port = None
            mole.torrent = None
            renewed = asyncio.Event()

            async def refresh():
                renewed.set()
                return True

            async def initial_renewal():
                mole.state.connected = True
                mole.state.port = 23456
                try:
                    await asyncio.wait_for(renewed.wait(), timeout=0.15)
                except asyncio.TimeoutError:
                    self.fail('initial client wait prevented lease keepalive from starting')
                mole.shutdown_event.set()
                return True

            mole.provider = Mock(refresh_port_forward=AsyncMock(side_effect=refresh))
            mole._full_renewal = AsyncMock(side_effect=initial_renewal)
            mole._watchdog_loop = AsyncMock()
            mole._restart_watcher_loop = AsyncMock()
            mole._cleanup = AsyncMock()
            with patch('mole_pkg.mole.setup_namespace'), patch.object(
                asyncio.get_running_loop(), 'add_signal_handler'
            ), patch('mole_pkg.mole.increment_counter'), patch(
                'mole_pkg.mole.increment_dict_counter'
            ), patch('mole_pkg.mole.atomic_write_state'):
                try:
                    await mole.run()
                finally:
                    tasks = [task for task in (mole._keepalive_task, mole._watchdog_task,
                                              mole._restart_watcher_task) if task is not None]
                    for task in tasks:
                        task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)


class ReviewedRecovery(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixtures.RecoveryOrchestration.setUp(self)

    async def test_registration_failure_preserves_installed_endpoint_for_reconciliation(self):
        self.mole._installed_server_ip = '192.0.2.1'
        self.mole._installed_peer_key = 'old-peer'
        self.mole._installed_generation = self.mole.state.generation
        self.mole.provider._select(self.servers[1])
        self.mole.provider.register_wireguard.return_value = False
        self.assertFalse(await self.mole._attempt_selected_server('192.0.2.1'))
        self.mole.provider._select(self.servers[2])
        with patch('mole_pkg.mole.allow_vpn_server_ip') as allowance, patch(
            'mole_pkg.mole.read_wg_peer_key', return_value='new-peer'
        ), patch('mole_pkg.mole.run_in_netns', return_value=Mock(returncode=0)) as command, patch.object(
            self.mole, '_wait_for_readiness', return_value=False
        ):
            await Mole._connect_vpn(self.mole, '192.0.2.2')
        self.assertEqual(allowance.call_args.args[2], '192.0.2.1')
        deleted = [call.args[0][3] for call in command.call_args_list if call.args[0][:3] == ['ip', 'route', 'del']]
        self.assertEqual(deleted, ['192.0.2.1'])

    async def test_watchdog_cannot_verify_old_interface_under_failed_candidate_generation(self):
        self.mole._installed_server_ip = '192.0.2.1'
        self.mole._installed_peer_key = 'old-peer'
        self.mole._installed_generation = self.mole.state.generation
        self.mole.provider._select(self.servers[1])
        self.mole.provider.register_wireguard.return_value = False
        await self.mole._attempt_selected_server('192.0.2.1')
        with patch('mole_pkg.mole.read_wg_peer_key', return_value='old-peer'), patch.object(
            self.mole, '_verify_transport', return_value=True
        ):
            self.assertFalse(await self.mole._check_health())

    async def test_old_client_writer_cannot_publish_readiness_for_new_generation(self):
        started, finish = asyncio.Event(), asyncio.Event()
        self.mole.state.peer_ip = '192.0.2.4'
        self.mole.state.port = 23456

        async def interface(*args):
            started.set()
            await finish.wait()
            return True

        self.mole.torrent = Mock(set_interface=AsyncMock(side_effect=interface), set_listen_port=AsyncMock(return_value=True))
        task = asyncio.create_task(self.mole._sync_torrent_binding())
        await started.wait()
        self.mole.state.generation += 1
        finish.set()
        self.assertFalse(await task)
        self.assertFalse(self.mole.state.client_ready)

    async def test_mapping_port_change_invalidates_client_readiness(self):
        from test_port_forward_renewal import mapping
        self.config._data['PORT_FORWARD'] = 'true'
        self.mole.state.port = 12345
        self.mole.state.client_ready = True
        with patch('mole_pkg.providers.proton.async_run_in_netns', side_effect=[mapping('UDP'), mapping('TCP')]):
            self.assertTrue(await self.mole.provider.refresh_port_forward())
        self.assertFalse(self.mole.state.client_ready)

    async def test_slow_client_lock_does_not_block_tunnel_monitoring(self):
        self.mole.state.peer_ip = '192.0.2.4'
        self.mole.state.server_ip = '192.0.2.1'
        self.mole.state.port = 23456
        self.mole._installed_server_ip = self.mole.state.server_ip
        self.mole._installed_peer_key = 'peer'
        self.mole._installed_generation = self.mole.state.generation
        self.mole.torrent = Mock(get_connection_status=AsyncMock(return_value='connected'))
        lock = self.mole._torrent_lock()
        await lock.acquire()
        try:
            with patch('mole_pkg.mole.read_wg_peer_key', return_value='peer'), patch.object(self.mole, '_verify_transport', return_value=True):
                self.assertTrue(await asyncio.wait_for(self.mole._check_health(), .05))
        finally:
            lock.release()
            task = getattr(self.mole, '_listener_task', None)
            if task:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_slow_initial_client_sync_does_not_occupy_renewal_owner(self):
        finish = asyncio.Event()
        self.mole.torrent = Mock()

        async def slow(*args, **kwargs):
            await finish.wait()
            return True

        self.mole._update_torrent_client = AsyncMock(side_effect=slow)
        try:
            self.assertTrue(await asyncio.wait_for(self.mole._full_renewal(), .05))
        finally:
            finish.set()
            task = self.mole._torrent_sync_task
            if task:
                await task

    async def test_strict_pin_is_found_in_later_configured_country(self):
        self.config._data.update(PROTON_FAILOVER_ENABLED='false', PROTON_COUNTRY='XX,YY', PROTON_SERVER='YY#1')
        self.servers[1].update(name='YY#1', country='YY')
        self.mole.provider._filter_servers = lambda values, country=None: [s for s in values if not country or s['country'] == country]
        self.assertTrue(await self.mole.provider.get_server())
        self.assertEqual(self.mole.state.server_ip, '192.0.2.2')

    async def test_port_endpoint_does_not_advertise_a_stale_saved_port(self):
        (Path(self.root.name) / 'port').write_text('23456')
        api = HTTPAPIServerStandalone('127.0.0.1', 0, '', self.root.name)
        status = (await api._get_port())['body']
        self.assertIsNone(status['port'])
        self.assertEqual(status['last_known_port'], 23456)
        self.assertFalse(status['forwarding_ready'])

    async def test_port_endpoint_uses_atomic_mapping_and_expires_it(self):
        from mole_pkg.utils import write_runtime_readiness
        self.mole.state.connected = self.mole.state.tunnel_ready = True
        self.mole.state.tunnel_deadline = time.monotonic() + 90
        self.mole.state.forwarding_ready = True
        self.mole.state.port = 23456
        self.mole.state.port_deadline = time.monotonic() + 30
        write_runtime_readiness(Path(self.root.name), self.mole.state)
        (Path(self.root.name) / 'port').write_text('12345')
        api = HTTPAPIServerStandalone('127.0.0.1', 0, '', self.root.name)
        self.assertEqual((await api._get_port())['body']['port'], 23456)
        with patch.object(api, '_run_cmd', return_value=Mock(returncode=0, stdout='')):
            self.assertIn('mole_vpn_forwarded_port 23456', (await api._get_metrics())['body'])
        with patch('mole_pkg.utils.time.monotonic', return_value=self.mole.state.port_deadline + 1):
            status = (await api._get_port())['body']
        self.assertIsNone(status['port'])
        self.assertFalse(status['forwarding_ready'])


class ReviewedCompatibility(unittest.TestCase):
    def test_proton_validation_still_checks_credentials_and_original_settings(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'config'
            path.write_text('VPN_PROVIDER=proton\nTORRENT_CLIENT=none\nPORT_FORWARD=false\nPROTON_NETSHIELD=invalid\n')
            valid, errors = validate_config(str(path))
            self.assertFalse(valid)
            self.assertIn('PROTON_USER is not set', errors)
            self.assertIn('PROTON_PASS is not set', errors)
            self.assertTrue(any('PROTON_NETSHIELD' in error for error in errors))

    def test_pia_runtime_imports_without_optional_proton_sdk(self):
        code = ('import sys; sys.modules["proton"] = None; '
                'from mole_pkg.mole import get_vpn_provider; '
                'from mole_pkg.config import Config; from mole_pkg.utils import VPNState; '
                'assert get_vpn_provider(Config("/nonexistent"), VPNState()).name == "PIA"')
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
