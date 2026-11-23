import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from mole_pkg import utils
from mole_pkg.config import Config
from mole_pkg.mole import Mole


class HandshakeEvidence(unittest.TestCase):
    def test_missing_stale_future_foreign_and_malformed_are_rejected(self):
        self.assertTrue(callable(getattr(utils, 'handshake_timestamp', None)))
        now = 2000
        for output in ('', 'peer 0', 'peer 1819', 'peer 2001', 'foreign 2000', 'peer bad', 'peer 2000 extra', 'peer 2000\npeer 1999'):
            with self.subTest(output=output):
                self.assertIsNone(utils.handshake_timestamp(output, 'peer', now, 1900))
        self.assertEqual(utils.handshake_timestamp('peer\t2000', 'peer', now, 1900), 2000)
        self.assertIsNone(utils.handshake_timestamp('peer 1999', 'peer', now, 2000))

    def test_peer_parser_rejects_ambiguous_config_without_exposing_private_key(self):
        self.assertTrue(callable(getattr(utils, 'read_wg_peer_key', None)))
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'wg.conf'
            path.write_text('[Interface]\nPrivateKey = synthetic-secret\n[Peer]\nPublicKey = peer\n')
            self.assertEqual(utils.read_wg_peer_key(str(path)), 'peer')
            path.write_text(path.read_text() + '[Peer]\nPublicKey = another\n')
            with self.assertRaises(ValueError) as error:
                utils.read_wg_peer_key(str(path))
            self.assertNotIn('synthetic-secret', str(error.exception))

    def test_probe_configuration_rejects_private_or_credential_urls(self):
        config = Config('/nonexistent')
        for value in ('http://example.org/,https://example.com/', 'https://127.0.0.1/,https://example.com/',
                      'https://user:secret@example.org/,https://example.com/', 'https://example.org/?token=secret,https://example.com/',
                      'https://localhost/,https://example.com/'):
            config._data['VPN_READY_PROBES'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                config.vpn_ready_probes


class TunnelReadiness(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.mole = Mole.__new__(Mole)
        self.mole.state = utils.VPNState()
        self.mole.config = Mock(netns='synthetic', vpn_ready_timeout=.04,
                                vpn_ready_probes=['https://example.org/', 'https://example.com/'],
                                watchdog_interval=60, state_dir=self.root.name)
        self.mole.torrent = None
        self.mole._attempt_wall = int(time.time())

    async def test_valid_tls_denial_and_intended_handshake_prove_egress(self):
        self.assertTrue(callable(getattr(self.mole, '_wait_for_readiness', None)))
        calls = []

        async def command(cmd, netns, timeout):
            calls.append(cmd)
            if cmd[0] == 'wg':
                return Mock(returncode=0, stdout=f'peer {int(time.time())}')
            return Mock(returncode=0, stdout='403')

        with patch('mole_pkg.mole.async_run_in_netns', create=True, side_effect=command):
            self.assertTrue(await self.mole._wait_for_readiness('peer', time.monotonic()))
        curl = next(cmd for cmd in calls if cmd[0] == 'curl')
        self.assertIn('--interface', curl)
        self.assertEqual(curl[curl.index('--interface') + 1], 'mole')
        self.assertIn('--noproxy', curl)
        self.assertIn('=https', curl)
        self.assertNotIn('--fail', curl)
        self.assertNotIn('-L', curl)
        self.assertFalse(any(cmd[0] == 'ping' for cmd in calls))

    async def test_one_target_failure_does_not_hide_working_tunnel(self):
        self.assertTrue(callable(getattr(self.mole, '_wait_for_readiness', None)))

        async def command(cmd, *args, **kwargs):
            if cmd[0] == 'wg':
                return Mock(returncode=0, stdout=f'peer {int(time.time())}')
            return Mock(returncode=1 if 'https://example.org/' in cmd else 0, stdout='200')

        with patch('mole_pkg.mole.async_run_in_netns', create=True, side_effect=command):
            self.assertTrue(await self.mole._wait_for_readiness('peer', time.monotonic()))

    async def test_no_handshake_or_no_egress_cannot_be_ready(self):
        self.assertTrue(callable(getattr(self.mole, '_wait_for_readiness', None)))
        for hs, code in [('', 0), ('peer 0', 0), (f'foreign {int(time.time())}', 0), (f'peer {int(time.time())}', 1)]:
            async def command(cmd, *args, **kwargs):
                return Mock(returncode=0 if cmd[0] == 'wg' else code, stdout=hs if cmd[0] == 'wg' else '200')
            with self.subTest(hs=hs, code=code), patch('mole_pkg.mole.async_run_in_netns', create=True, side_effect=command):
                self.assertFalse(await self.mole._wait_for_readiness('peer', time.monotonic()))
        self.assertFalse(self.mole.state.connected)

    async def test_probe_deadline_and_cancellation_propagate(self):
        self.assertTrue(callable(getattr(self.mole, '_wait_for_readiness', None)))

        async def stalled(*args, **kwargs):
            await asyncio.sleep(30)

        with patch('mole_pkg.mole.async_run_in_netns', create=True, side_effect=stalled):
            started = time.monotonic()
            self.assertFalse(await self.mole._wait_for_readiness('peer', started))
            self.assertLess(time.monotonic() - started, .2)
            task = asyncio.create_task(self.mole._wait_for_readiness('peer', time.monotonic()))
            await asyncio.sleep(.005)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

    async def test_connect_cannot_claim_ready_without_handshake(self):
        self.mole.config.wg_conf = 'synthetic.conf'
        self.mole.config.veth_host_ip = '192.0.2.1'
        self.mole.state.server_ip = '198.51.100.1'
        self.mole.state.connected = self.mole.state.tunnel_ready = True
        with patch('mole_pkg.mole.read_wg_peer_key', return_value='peer'), patch(
            'mole_pkg.mole.run_in_netns', return_value=Mock(returncode=0, stdout='', stderr='')
        ), patch('mole_pkg.mole.allow_vpn_server_ip'), patch(
            'mole_pkg.mole.async_run_in_netns', return_value=Mock(returncode=0, stdout='')
        ):
            self.assertFalse(await self.mole._connect_vpn(None))
        self.assertFalse(self.mole.state.connected)
        self.assertEqual(self.mole.state.generation, 1)

    async def test_old_probe_cannot_invalidate_new_generation(self):
        async def rotate(*args, **kwargs):
            self.mole.state.generation += 1
            self.mole.state.connected = self.mole.state.tunnel_ready = True
            return Mock(returncode=1, stdout='')

        with patch('mole_pkg.mole.async_run_in_netns', side_effect=rotate):
            self.assertFalse(await self.mole._wait_for_readiness('peer', time.monotonic()))
        self.assertTrue(self.mole.state.connected)


class LegacyRuntime(unittest.TestCase):
    def test_run_uses_the_shared_orchestrator(self):
        import runpy
        import sys
        module = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'mole'), run_name='legacy_mole_test')
        with patch.object(sys, 'argv', ['mole', 'run']), patch('mole_pkg.mole.Mole') as runtime:
            runtime.return_value.run = AsyncMock()
            module['main'].__globals__['Mole'] = Mock(side_effect=AssertionError('legacy runtime used'))
            with patch('mole_pkg.cli.validate_config', return_value=(True, [])):
                self.assertEqual(module['main'](), 0)
            runtime.assert_called_once()

    def test_legacy_runtime_respects_shared_configuration_gate(self):
        import runpy
        import sys
        module = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'mole'), run_name='legacy_mole_test')
        with patch.object(sys, 'argv', ['mole', 'run']), patch('mole_pkg.cli.validate_config', return_value=(False, ['invalid configuration'])), patch('mole_pkg.mole.Mole') as runtime:
            self.assertEqual(module['main'](), 1)
            runtime.assert_not_called()


class RuntimeReadiness(unittest.TestCase):
    def test_runtime_rejects_restart_truncation_generation_and_expired_lease(self):
        self.assertTrue(callable(getattr(utils, 'read_runtime_readiness', None)))
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            state = utils.VPNState()
            state.generation = 2
            state.connected = state.tunnel_ready = True
            state.tunnel_deadline = time.monotonic() + 60
            state.forwarding_ready = True
            state.port = 12345
            state.port_deadline = time.monotonic() + 30
            utils.write_runtime_readiness(directory, state)
            self.assertTrue(utils.read_runtime_readiness(directory)['connected'])
            self.assertTrue(utils.read_runtime_readiness(directory)['forwarding_ready'])
            with patch('mole_pkg.utils.time.monotonic', return_value=state.port_deadline + 1):
                self.assertFalse(utils.read_runtime_readiness(directory)['forwarding_ready'])
            evidence = json.loads((directory / 'runtime_readiness.json').read_text())
            evidence['process_identity'] = 'previous-process'
            (directory / 'runtime_readiness.json').write_text(json.dumps(evidence))
            self.assertFalse(utils.read_runtime_readiness(directory)['connected'])
            utils.write_runtime_readiness(directory, state)
            (directory / 'runtime_generation').write_text('3')
            self.assertFalse(utils.read_runtime_readiness(directory)['connected'])
            (directory / 'runtime_readiness.json').write_text('{')
            self.assertFalse(utils.read_runtime_readiness(directory)['connected'])


class ApiReadiness(unittest.IsolatedAsyncioTestCase):
    async def test_existing_interface_and_saved_port_do_not_prove_health(self):
        from mole_pkg.services.api_main import HTTPAPIServerStandalone, format_prometheus_metrics
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / 'port').write_text('12345')
            server = HTTPAPIServerStandalone('127.0.0.1', 0, '', root)
            with patch.object(server, '_run_cmd', return_value=Mock(returncode=0, stdout='')):
                status = (await server._get_status())['body']
            self.assertFalse(status['connected'])
            self.assertFalse(status['tunnel_ready'])
            self.assertFalse(status['forwarding_ready'])
            self.assertEqual(status['port'], 12345)
            metrics = format_prometheus_metrics({}, status)
            self.assertIn('mole_vpn_tunnel_ready 0', metrics)
