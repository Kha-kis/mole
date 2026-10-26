import asyncio
import tempfile
import threading
import time
import unittest
import json
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from mole_pkg.mole import Mole
from mole_pkg.providers import ProtonProvider
from mole_pkg.services.qbittorrent import QBittorrentClient
from mole_pkg.utils import VPNState


def mapping(protocol, port=23456, lifetime=60, returncode=0):
    return Mock(
        returncode=returncode,
        stdout=f"Mapped public port {port} protocol {protocol} to local port 0 lifetime {lifetime}\n",
        stderr="request failed" if returncode else "",
    )


class TestProtonMappingRenewal(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Mock(state_dir=self.directory.name, port_forward=True, netns="test-vpn")
        self.config.get.side_effect = lambda key, default="": default
        self.state = VPNState()
        self.state.port = 12345
        self.state.port_expires = datetime.now() - timedelta(seconds=1)
        self.previous_expiry = self.state.port_expires
        self.provider = ProtonProvider(self.config, self.state)

    async def test_refresh_adopts_and_persists_changed_port(self):
        with patch("mole_pkg.providers.proton.run_in_netns", side_effect=[mapping("UDP"), mapping("TCP")]):
            self.assertTrue(await self.provider.refresh_port_forward())
        self.assertEqual(self.state.port, 23456)
        self.assertEqual((Path(self.directory.name) / "port").read_text().strip(), "23456")
        self.assertGreater(self.state.port_expires, datetime.now())

    async def test_failed_or_invalid_mapping_does_not_claim_success(self):
        cases = [
            [mapping("UDP", returncode=1)],
            [mapping("UDP"), mapping("TCP", returncode=1)],
            [mapping("UDP"), mapping("TCP", port=34567)],
            [mapping("UDP", port=0)],
            [mapping("UDP", port=65536)],
            [mapping("UDP", lifetime=0)],
            [mapping("TCP")],
            [Mock(returncode=0, stdout="unparseable response", stderr="")],
            [mapping("UDP"), mapping("TCP", lifetime=0)],
        ]
        for responses in cases:
            with self.subTest(responses=responses), patch(
                "mole_pkg.providers.proton.run_in_netns", side_effect=responses
            ):
                self.assertFalse(await self.provider.refresh_port_forward())
                self.assertEqual(self.state.port, 12345)
                self.assertEqual(self.state.port_expires, self.previous_expiry)

    async def test_setup_requires_both_protocols_to_agree(self):
        with patch("mole_pkg.providers.proton.run_cmd", return_value=Mock(returncode=0)), patch(
            "mole_pkg.providers.proton.run_in_netns", side_effect=[mapping("UDP"), mapping("TCP", port=34567)]
        ):
            self.assertFalse(await self.provider.setup_port_forward())
        self.assertEqual(self.state.port, 12345)

    async def test_setup_persists_valid_mapping(self):
        with patch("mole_pkg.providers.proton.run_cmd", return_value=Mock(returncode=0)), patch(
            "mole_pkg.providers.proton.run_in_netns", side_effect=[mapping("UDP"), mapping("TCP")]
        ):
            self.assertTrue(await self.provider.setup_port_forward())
        self.assertEqual(self.state.port, 23456)

    async def test_expiry_uses_shorter_protocol_lease(self):
        before = datetime.now()
        with patch("mole_pkg.providers.proton.run_in_netns", side_effect=[mapping("UDP", lifetime=50), mapping("TCP", lifetime=40)]):
            self.assertTrue(await self.provider.refresh_port_forward())
        self.assertLessEqual(self.state.port_expires, datetime.now() + timedelta(seconds=40))
        self.assertGreaterEqual(self.state.port_expires, before + timedelta(seconds=40))

    async def test_disabled_forwarding_does_not_request_mapping(self):
        self.config.port_forward = False
        with patch("mole_pkg.providers.proton.run_in_netns") as run:
            self.assertTrue(await self.provider.refresh_port_forward())
        run.assert_not_called()


class TestKeepaliveTorrentPortSync(unittest.IsolatedAsyncioTestCase):
    async def run_iterations(self, torrent_results, refresh_ok=True, initial_port=12345, sync_delay=0):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        mole = Mole.__new__(Mole)
        mole.config = Mock(port_forward=True, keepalive_interval=0, state_dir=directory.name)
        mole.state = VPNState()
        mole.state.connected = True
        mole.state.port = initial_port
        mole.state.peer_ip = "192.0.2.2"
        mole.state.server_country = "XX"
        mole.shutdown_event = asyncio.Event()
        mole._torrent_update_lock = asyncio.Lock()
        mole._torrent_sync_task = None
        results = iter(torrent_results)

        async def sync_port(port):
            if sync_delay:
                await asyncio.sleep(sync_delay)
            result = next(results)
            if isinstance(result, Exception):
                raise result
            return result

        mole.torrent = Mock(
            set_listen_port=AsyncMock(side_effect=sync_port),
            set_interface=AsyncMock(return_value=True),
        )
        remaining = len(torrent_results)

        async def refresh():
            nonlocal remaining
            if refresh_ok:
                mole.state.port = 23456
            remaining -= 1
            if not remaining:
                mole.shutdown_event.set()
            return refresh_ok

        mole.provider = Mock(
            refresh_port_forward=AsyncMock(side_effect=refresh),
            setup_port_forward=AsyncMock(side_effect=refresh),
        )
        with patch("mole_pkg.mole.increment_counter") as counter, patch(
            "mole_pkg.mole.increment_dict_counter"
        ), patch("mole_pkg.mole.atomic_write_state"):
            started = time.monotonic()
            await asyncio.wait_for(mole._keepalive_loop(), timeout=2)
            mole._test_keepalive_duration = time.monotonic() - started
            task = mole._torrent_sync_task
            if task is not None:
                await asyncio.gather(task, return_exceptions=True)
        return mole, [call.args[1] for call in counter.call_args_list]

    async def test_changed_port_is_sent_to_torrent_client(self):
        mole, counters = await self.run_iterations([True])
        mole.torrent.set_listen_port.assert_awaited_once_with(23456)
        self.assertEqual(counters, ["port_forward_renewals_success_total"])

    async def test_torrent_sync_failure_is_retried_next_keepalive(self):
        mole, counters = await self.run_iterations([False, True])
        self.assertEqual(mole.torrent.set_listen_port.await_count, 2)
        self.assertEqual(counters, ["port_forward_renewals_success_total"] * 2)

    async def test_torrent_sync_exception_does_not_mislabel_valid_lease(self):
        _, counters = await self.run_iterations([RuntimeError("unavailable")])
        self.assertEqual(counters, ["port_forward_renewals_success_total"])

    async def test_failed_renewal_does_not_update_torrent_port(self):
        mole, counters = await self.run_iterations([True], refresh_ok=False)
        mole.torrent.set_listen_port.assert_not_awaited()
        self.assertEqual(counters, ["port_forward_renewals_failure_total"])

    async def test_keepalive_retries_initial_mapping_failure(self):
        mole, counters = await self.run_iterations([True], initial_port=None)
        mole.provider.setup_port_forward.assert_awaited_once()
        mole.provider.refresh_port_forward.assert_not_awaited()
        mole.torrent.set_listen_port.assert_awaited_once_with(23456)
        mole.torrent.set_interface.assert_awaited_once_with("mole", "192.0.2.2")
        self.assertEqual(counters, ["port_forward_renewals_success_total"])

    async def test_slow_torrent_sync_does_not_delay_keepalive_loop(self):
        mole, counters = await self.run_iterations([True], sync_delay=0.2)
        self.assertLess(mole._test_keepalive_duration, 0.15)
        self.assertEqual(counters, ["port_forward_renewals_success_total"])

    async def test_interface_binding_succeeds_without_forwarded_port(self):
        mole = Mole.__new__(Mole)
        mole.state = VPNState()
        mole.state.peer_ip = "192.0.2.2"
        mole._torrent_update_lock = asyncio.Lock()
        mole.torrent = Mock(
            set_interface=AsyncMock(return_value=True),
            set_listen_port=AsyncMock(return_value=True),
        )
        self.assertTrue(await mole._sync_torrent_binding())
        mole.torrent.set_interface.assert_awaited_once_with("mole", "192.0.2.2")
        mole.torrent.set_listen_port.assert_not_awaited()

    async def test_keepalive_skips_disabled_forwarding(self):
        mole = Mole.__new__(Mole)
        mole.config = Mock(port_forward=False, keepalive_interval=0, state_dir="/unused")
        mole.state = VPNState()
        mole.state.connected = True
        mole.shutdown_event = asyncio.Event()
        mole.provider = Mock(setup_port_forward=AsyncMock(return_value=True))
        mole.torrent = None

        async def stop_after_one_iteration(delay):
            mole.shutdown_event.set()

        with patch("mole_pkg.mole.asyncio.sleep", side_effect=stop_after_one_iteration), patch(
            "mole_pkg.mole.increment_counter"
        ), patch("mole_pkg.mole.increment_dict_counter"), patch("mole_pkg.mole.atomic_write_state"):
            await mole._keepalive_loop()
        mole.provider.setup_port_forward.assert_not_awaited()

    async def test_watchdog_cannot_restore_old_port_after_new_port_sync(self):
        mole = Mole.__new__(Mole)
        mole.state = VPNState()
        mole.state.port = 12345
        mole.state.peer_ip = "192.0.2.2"
        mole._torrent_update_lock = asyncio.Lock()
        started, finish = asyncio.Event(), asyncio.Event()
        writes = []

        async def toggle(port):
            started.set()
            await finish.wait()
            writes.append(port)
            return True

        async def set_port(port):
            writes.append(port)
            return True

        mole.torrent = Mock(
            get_connection_status=AsyncMock(return_value="disconnected"),
            _toggle_port=AsyncMock(side_effect=toggle),
            set_interface=AsyncMock(return_value=True),
            set_listen_port=AsyncMock(side_effect=set_port),
        )
        watchdog = asyncio.create_task(mole._check_torrent_listener())
        await asyncio.wait_for(started.wait(), timeout=1)
        mole.state.port = 23456
        synchronization = asyncio.create_task(mole._sync_torrent_binding())
        await asyncio.sleep(0)
        finish.set()
        await asyncio.wait_for(asyncio.gather(watchdog, synchronization), timeout=1)
        self.assertEqual(writes, [12345, 23456])


class TestTorrentApiDoesNotBlockRenewal(unittest.IsolatedAsyncioTestCase):
    async def test_cleanup_drains_watchdog_before_disconnect(self):
        mole = Mole.__new__(Mole)
        mole.config = Mock(post_disconnect_hook='')
        mole._keepalive_task = None
        mole._restart_watcher_task = None
        mole._torrent_sync_task = None
        mole._api_proc = mole._proxy_proc = mole._dns_proc = None
        started = asyncio.Event()
        finished = False

        async def writer():
            nonlocal finished
            try:
                started.set()
                await asyncio.Event().wait()
            finally:
                await asyncio.sleep(0.01)
                finished = True

        mole._watchdog_task = asyncio.create_task(writer())
        await started.wait()
        with patch.object(mole, '_stop_subprocess'), patch.object(mole, '_run_hook'), patch(
            'mole_pkg.mole.disconnect_vpn', side_effect=lambda config: self.assertTrue(finished)
        ):
            try:
                await mole._cleanup()
            finally:
                await asyncio.gather(mole._watchdog_task, return_exceptions=True)

    async def test_slow_api_drain_does_not_delay_second_mapping_renewal(self):
        client = QBittorrentClient(Mock(qb_api_url='http://qbit.test/api/v2/app',
                                      qb_api_timeout=120, qb_api_auth_file=''))
        with tempfile.TemporaryDirectory() as directory:
            mole = Mole.__new__(Mole)
            mole.config = Mock(port_forward=True, keepalive_interval=0.02, state_dir=directory)
            mole.state = VPNState(connected=True, port=23456, peer_ip='192.0.2.2')
            mole.shutdown_event = asyncio.Event()
            mole._torrent_update_lock = asyncio.Lock()
            mole._torrent_sync_task = None
            mole.torrent = client
            times = []

            async def refresh():
                times.append(time.monotonic())
                if len(times) == 2:
                    mole.shutdown_event.set()
                return True

            def slow_request(*args, **kwargs):
                time.sleep(0.2)
                response = Mock()
                response.__enter__ = Mock(return_value=response)
                response.__exit__ = Mock(return_value=False)
                response.read.return_value = b'{}'
                return response

            mole.provider = Mock(refresh_port_forward=AsyncMock(side_effect=refresh))
            with patch('mole_pkg.services.qbittorrent.urllib.request.urlopen', side_effect=slow_request), patch(
                'mole_pkg.mole.increment_counter'
            ), patch('mole_pkg.mole.increment_dict_counter'), patch(
                'mole_pkg.mole.atomic_write_state'
            ):
                try:
                    await mole._keepalive_loop()
                finally:
                    if mole._torrent_sync_task is not None:
                        mole._torrent_sync_task.cancel()
                        try:
                            await mole._torrent_sync_task
                        except asyncio.CancelledError:
                            pass
            self.assertLess(times[1] - times[0], 0.12)

    async def test_repeated_cancellation_drains_inflight_write(self):
        client = QBittorrentClient(Mock(qb_api_url='http://qbit.test/api/v2/app',
                                      qb_api_timeout=15, qb_api_auth_file=''))
        entered, release, completed = threading.Event(), threading.Event(), threading.Event()

        def blocked_request(*args, **kwargs):
            entered.set()
            release.wait(2)
            completed.set()
            response = Mock()
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read.return_value = b''
            return response

        with patch('mole_pkg.services.qbittorrent.urllib.request.urlopen', side_effect=blocked_request):
            task = asyncio.create_task(client._fetch(client._request('http://qbit.test/write')))
            await asyncio.get_running_loop().run_in_executor(None, entered.wait, 1)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            await asyncio.sleep(0.01)
            pending = not task.done()
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(pending, 'cancelled writer must retain its lock until HTTP finishes')
        self.assertTrue(completed.is_set())

    async def test_cancelled_toggle_restores_forwarded_port(self):
        client = QBittorrentClient(Mock(qb_api_url='http://qbit.test/api/v2/app',
                                      qb_api_timeout=15, qb_api_auth_file=''))
        writes = []
        entered = asyncio.Event()

        async def fetch(request, timeout=None):
            payload = urllib.parse.parse_qs(request.data.decode())
            writes.append(json.loads(payload['json'][0])['listen_port'])
            return b''

        async def pause(delay):
            entered.set()
            await asyncio.Event().wait()

        with patch.object(client, '_fetch', side_effect=fetch), patch(
            'mole_pkg.services.qbittorrent.asyncio.sleep', side_effect=pause
        ):
            task = asyncio.create_task(client._toggle_port(23456))
            await asyncio.wait_for(entered.wait(), timeout=1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(writes, [23455, 23456])

    async def test_fetch_does_not_require_python39_to_thread(self):
        config = Mock(qb_api_url="http://qbit.test/api/v2/app", qb_api_timeout=15, qb_api_auth_file="")
        client = QBittorrentClient(config)
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"listen_port":23456}'
        with patch("asyncio.to_thread", None, create=True), patch(
            "mole_pkg.services.qbittorrent.urllib.request.urlopen", return_value=response
        ):
            self.assertEqual(await client.get_listen_port(), 23456)

    async def test_cancellation_waits_for_inflight_request_before_releasing_writer(self):
        config = Mock(qb_api_url="http://qbit.test/api/v2/app", qb_api_timeout=15, qb_api_auth_file="")
        client = QBittorrentClient(config)
        started, completed = threading.Event(), threading.Event()

        def slow_write(*args, **kwargs):
            started.set()
            time.sleep(0.05)
            completed.set()
            response = Mock()
            response.read.return_value = b""
            context = Mock()
            context.__enter__ = Mock(return_value=response)
            context.__exit__ = Mock(return_value=False)
            return context

        with patch("mole_pkg.services.qbittorrent.urllib.request.urlopen", side_effect=slow_write):
            task = asyncio.create_task(client._fetch(client._request("http://qbit.test/api/v2/app/setPreferences")))
            await asyncio.get_running_loop().run_in_executor(None, started.wait, 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(completed.is_set(), "cancelled writer can still overwrite newer settings")

    async def test_slow_http_does_not_block_event_loop(self):
        config = Mock(qb_api_url="http://qbit.test/api/v2/app", qb_api_timeout=15, qb_api_auth_file="")
        client = QBittorrentClient(config)

        def slow_open(*args, **kwargs):
            time.sleep(0.1)
            response = Mock()
            response.read.return_value = b'{"listen_port":23456}'
            context = Mock()
            context.__enter__ = Mock(return_value=response)
            context.__exit__ = Mock(return_value=False)
            return context

        with patch("mole_pkg.services.qbittorrent.urllib.request.urlopen", side_effect=slow_open):
            task = asyncio.create_task(client.get_listen_port())
            await asyncio.sleep(0.01)
            was_pending = not task.done()
            self.assertEqual(await task, 23456)
            self.assertTrue(was_pending, "qBittorrent HTTP blocked the renewal event loop")


class TestLockConstruction(unittest.TestCase):
    def test_constructor_does_not_bind_writer_lock_to_an_unused_event_loop(self):
        with patch('mole_pkg.mole.Config'), patch('mole_pkg.mole.get_vpn_provider'), patch(
            'mole_pkg.mole.get_torrent_client'
        ), patch('mole_pkg.mole.asyncio.Lock', side_effect=AssertionError('lock constructed outside run loop')):
            Mole('/nonexistent/mole-unit-test-config')
