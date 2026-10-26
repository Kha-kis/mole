"""PR-review regressions: no live services, credentials or network calls."""
import asyncio
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

from mole_pkg.mole import Mole
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
