import asyncio
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mole_pkg.config import Config
from mole_pkg.utils import VPNState
from mole_pkg.providers import proton


class SDKFailureClassification(unittest.TestCase):
    def test_only_typed_transport_and_retryable_http_errors_are_transient(self):
        from mole_pkg.providers.proton_worker import classify_error

        class APIError(Exception):
            pass

        for code, expected in [(429, 'transient'), (503, 'transient'),
                               (401, 'credentials_rejected'), (403, 'credentials_rejected'),
                               (5003, 'compatibility'), (400, 'invalid_response')]:
            error = APIError('synthetic-secret-token')
            error.code = code
            self.assertEqual(classify_error(error), expected)
        self.assertEqual(classify_error(TimeoutError()), 'transient')
        self.assertEqual(classify_error(ConnectionError()), 'transient')
        self.assertEqual(classify_error(ValueError('429 timeout password')), 'invalid_response')
        self.assertEqual(classify_error(RuntimeError('503')), 'local_state')

    def test_parent_errors_expose_finite_kind_not_sdk_details(self):
        error = proton.SDKFailure('credentials_rejected')
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(error.kind, 'credentials_rejected')
        self.assertNotIn('token', str(error))


class RealLocalSDKLoad(unittest.IsolatedAsyncioTestCase):
    @unittest.skipIf(proton.ProtonAPISession is None, 'optional SDK not installed')
    async def test_real_sdk_load_is_local_bounded_and_preserves_synthetic_session(self):
        with tempfile.TemporaryDirectory() as root:
            config = Config('/nonexistent')
            config._data.update(STATE_DIR=root, PROTON_USER='fixture')
            path = Path(root) / 'proton_session.json'
            path.write_text(json.dumps(dict(api_url=proton.PROTON_API_URL, appversion='linux-vpn@4.19.1',
                **{'User-Agent': 'fixture'}, cookies={'fixture': 'cookie'},
                session_data=dict(UID='fixture-local-uid', AccessToken='fixture-access', RefreshToken='fixture-refresh'))))
            path.chmod(0o600)
            provider = proton.ProtonProvider(config, VPNState())
            result = await provider._run_sdk_job('load')
            self.assertEqual(result, {'uid': 'fixture-local-uid'})
            self.assertEqual(json.loads(path.read_text())['cookies'], {'fixture': 'cookie'})
            self.assertEqual(list(Path(root).glob('.proton-job-*')), [])


class OfflinePreparation(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from test_discovery import KEY, logical
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.config = Config('/nonexistent')
        self.config._data.update(STATE_DIR=self.directory.name, VPN_PROVIDER='proton',
            PROTON_RECOVERY_MODE='validated', PROTON_FAILOVER_ENABLED='true',
            PROTON_FAILOVER_SERVERS='NL#1', PROTON_USER='fixture', PROTON_PASS='fixture')
        self.session = self.path / 'proton_session.json'
        self.session.write_text(json.dumps(dict(api_url=proton.PROTON_API_URL,
            session_data=dict(UID='fixture-uid', AccessToken='fixture-access', RefreshToken='fixture-refresh'))))
        self.session.chmod(0o600)
        self.cert = self.path / 'proton_certificate.json'
        self.cert.write_text(json.dumps(dict(x25519_private_key=KEY, ed25519_public_key=KEY,
            expiration_time=time.time() + 86400, device_name='fixture')))
        self.cert.chmod(0o600)
        self.logical = logical()

    def provider(self, failure=None):
        from unittest.mock import AsyncMock
        provider = proton.ProtonProvider(self.config, VPNState())
        async def job(operation, endpoint='', method='GET', data=None):
            if operation == 'load':
                return dict(uid='fixture-uid')
            if failure:
                raise proton.SDKFailure(failure)
            if endpoint == '/vpn/v2':
                return dict(Code=1000, VPN=dict(MaxTier=2))
            if endpoint == '/vpn/logicals':
                return dict(Code=1000, LogicalServers=[self.logical])
            if endpoint == '/vpn/v1/certificate':
                return dict(Code=1000, ExpirationTime=time.time() + 86400)
            raise AssertionError('unexpected online operation')
        provider._run_sdk_job = AsyncMock(side_effect=job)
        return provider

    async def test_cold_process_offline_preparation_reuses_bound_certificate_without_auth(self):
        warm = self.provider()
        self.assertTrue(await warm.prepare_recovery())
        cold = self.provider('transient')
        before = self.cert.read_bytes()
        self.assertTrue(await cold.prepare_recovery())
        self.assertEqual(cold.state.discovery_source, 'cache')
        self.assertTrue(await cold.get_server())
        self.assertEqual(cold._selected_server['entry_ip'], '1.1.1.1')
        self.assertEqual(self.cert.read_bytes(), before)
        self.assertNotIn('authenticate', [call.args[0] for call in cold._run_sdk_job.call_args_list])

    async def test_known_rejection_then_timeout_restart_never_restores_cache(self):
        self.assertTrue(await self.provider().prepare_recovery())
        self.assertFalse(await self.provider('credentials_rejected').prepare_recovery())
        self.assertFalse(await self.provider('transient').prepare_recovery())

    async def test_unpersistable_pending_prevents_online_request(self):
        from mole_pkg.discovery import RejectionJournal
        provider = self.provider()
        with patch.object(RejectionJournal, 'begin', side_effect=OSError('fixture')):
            self.assertFalse(await provider.prepare_recovery())
        self.assertNotIn('/vpn/v2', [call.args[1] for call in provider._run_sdk_job.call_args_list
                                   if len(call.args) > 1])

    async def test_changed_binding_or_expired_certificate_cannot_use_cache(self):
        self.assertTrue(await self.provider().prepare_recovery())
        value = json.loads(self.cert.read_text())
        value['expiration_time'] = time.time()
        self.cert.write_text(json.dumps(value))
        self.assertFalse(await self.provider('transient').prepare_recovery())

    async def test_new_entitlement_restriction_survives_discovery_timeout_and_restart(self):
        self.assertTrue(await self.provider().prepare_recovery())
        restricted = self.provider()
        original = restricted._run_sdk_job.side_effect
        async def job(operation, endpoint='', method='GET', data=None):
            if endpoint == '/vpn/v2':
                return dict(Code=1000, VPN=dict(MaxTier=0))
            if endpoint == '/vpn/logicals':
                raise proton.SDKFailure('transient')
            return await original(operation, endpoint, method, data)
        restricted._run_sdk_job.side_effect = job
        self.assertFalse(await restricted.prepare_recovery())
        self.assertFalse(await self.provider('transient').prepare_recovery())

    async def test_orchestrator_cold_offline_cycle_reuses_saved_certificate(self):
        from mole_pkg.mole import Mole
        from unittest.mock import AsyncMock
        self.config._data.update(PORT_FORWARD='false', TORRENT_CLIENT='none',
                                 WG_CONF=str(self.path / 'mole.conf'))
        self.assertTrue(await self.provider().prepare_recovery())
        file = self.path / 'config'
        file.write_text('\n'.join(key + '=' + value for key, value in self.config._data.items()))
        mole = Mole(str(file))
        cold = self.provider('transient')
        mole.provider, mole.state = cold, cold.state
        async def connect(old):
            mole.state.connected = mole.state.tunnel_ready = True
            return True
        mole._connect_vpn = AsyncMock(side_effect=connect)
        self.assertTrue(await mole._full_renewal())
        self.assertTrue(mole.state.connected)
        self.assertEqual(mole.state.discovery_source, 'cache')
        self.assertEqual(cold._selected_server['entry_ip'], '1.1.1.1')
        self.assertTrue((self.path / 'mole.conf').is_file())

    async def test_expired_access_refreshes_once_and_requires_full_online_revalidation(self):
        provider = self.provider()
        original = provider._run_sdk_job.side_effect
        refreshed = False
        async def job(operation, endpoint='', method='GET', data=None):
            nonlocal refreshed
            if operation == 'refresh':
                refreshed = True
                return dict(authenticated=True)
            if endpoint == '/vpn/v2' and not refreshed:
                raise proton.SDKFailure('credentials_rejected')
            return await original(operation, endpoint, method, data)
        provider._run_sdk_job.side_effect = job
        self.assertTrue(await provider.prepare_recovery())
        self.assertEqual(provider.state.discovery_source, 'live')
        self.assertEqual([c.args[0] for c in provider._run_sdk_job.call_args_list].count('refresh'), 1)
        self.assertNotIn('authenticate', [c.args[0] for c in provider._run_sdk_job.call_args_list])


class ProtonWorkers(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name)
        config = Config('/nonexistent')
        config._data.update(STATE_DIR=self.root.name, PROTON_USER='fixture', PROTON_PASS='synthetic-password')
        self.provider = proton.ProtonProvider(config, VPNState())
        self.session = self.path / 'proton_session.json'
        self.saved = {'cookies': {'a': 'b'}, 'session_data': {'AccessToken': 'synthetic'}}
        self.session.write_text(json.dumps(self.saved))
        fixture = str(Path(__file__).parent / 'fixtures/fake_proton')
        self.env = patch.dict(os.environ, PYTHONPATH=fixture)
        self.env.start()
        self.addCleanup(self.env.stop)

    def require_interface(self):
        self.assertTrue(callable(getattr(self.provider, '_run_sdk_job', None)))

    async def wait_marker(self):
        for _ in range(200):
            if (self.path / 'marker').exists():
                return
            await asyncio.sleep(.005)
        self.fail('offline SDK did not start')

    def delayed(self, delay):
        self.saved.update(delay=delay, marker=str(self.path / 'marker'))
        self.session.write_text(json.dumps(self.saved))

    async def test_delayed_sdk_keeps_heartbeat_and_preserves_session_fields(self):
        self.require_interface()
        self.delayed(.15)
        beats = []

        async def heartbeat():
            await asyncio.sleep(.01)
            beats.append(time.monotonic())

        start = time.monotonic()
        result, _ = await asyncio.gather(
            self.provider._run_sdk_job('api', '/vpn/logicals'), heartbeat())
        self.assertEqual(result['Code'], 1000)
        self.assertLess(beats[0] - start, .1)
        saved = json.loads(self.session.read_text())
        self.assertEqual(saved['cookies'], {'a': 'b'})
        self.assertEqual(saved['session_data'], {'AccessToken': 'synthetic'})
        self.assertEqual(saved['calls'], 1)
        self.assertEqual(list(self.path.glob('.proton-job-*')), [])
        self.assertEqual(self.session.stat().st_mode & 0o777, 0o600)

    async def test_stuck_sdk_timeout_does_not_adopt_staged_session(self):
        self.require_interface()
        self.delayed(30)
        before = self.session.read_bytes()
        original = proton.async_run_command

        async def bounded(cmd, timeout, **kwargs):
            self.assertEqual(timeout, 45)
            return await original(cmd, .15, **kwargs)

        with patch.object(proton, 'async_run_command', side_effect=bounded):
            with self.assertRaises(RuntimeError):
                await self.provider._run_sdk_job('api', '/vpn/logicals')
        self.assertEqual(self.session.read_bytes(), before)
        self.assertEqual(list(self.path.glob('.proton-job-*')), [])

    async def test_cancel_after_staged_write_never_changes_live_session(self):
        self.require_interface()
        self.delayed(30)
        before = self.session.read_bytes()
        task = asyncio.create_task(self.provider._run_sdk_job('api', '/vpn/logicals'))
        await self.wait_marker()
        staged = list(self.path.glob('.proton-job-*/session.json'))
        self.assertEqual(len(staged), 1)
        self.assertNotEqual(staged[0].read_bytes(), before)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.session.read_bytes(), before)
        self.assertEqual(list(self.path.glob('.proton-job-*')), [])

    async def test_generation_change_rejects_successful_old_job(self):
        self.require_interface()
        self.delayed(.1)
        before = self.session.read_bytes()
        task = asyncio.create_task(self.provider._run_sdk_job('api', '/vpn/logicals'))
        await self.wait_marker()
        self.provider.state.generation += 1
        with self.assertRaises(RuntimeError):
            await task
        self.assertEqual(self.session.read_bytes(), before)

    async def test_live_session_edit_is_not_overwritten(self):
        self.require_interface()
        self.delayed(.1)
        task = asyncio.create_task(self.provider._run_sdk_job('api', '/vpn/logicals'))
        await self.wait_marker()
        self.session.write_text('{"newer":true}')
        with self.assertRaises(RuntimeError):
            await task
        self.assertEqual(self.session.read_text(), '{"newer":true}')

    async def test_jobs_serialize_and_read_latest_session(self):
        self.require_interface()
        self.delayed(.05)
        first, second = await asyncio.gather(
            self.provider._run_sdk_job('api', '/vpn/logicals'),
            self.provider._run_sdk_job('api', '/vpn/logicals'))
        self.assertEqual((first['calls'], second['calls']), (1, 2))
        self.assertEqual(json.loads(self.session.read_text())['calls'], 2)

    async def test_worker_errors_do_not_disclose_sdk_output(self):
        self.require_interface()
        self.saved['error'] = True
        self.session.write_text(json.dumps(self.saved))
        with self.assertRaises(RuntimeError) as error:
            await self.provider._run_sdk_job('api', '/vpn/logicals')
        self.assertNotIn('synthetic-secret-token', str(error.exception))

    async def test_rejects_unapproved_dispatch_before_spawning(self):
        self.require_interface()
        for operation, endpoint, method in [('shell', '', 'GET'), ('api', '/vpn/logicals', 'DELETE'),
                                            ('api', '/unapproved', 'GET')]:
            with self.subTest(operation=operation, endpoint=endpoint), self.assertRaises(ValueError):
                await self.provider._run_sdk_job(operation, endpoint, method)

    async def test_authentication_uses_120_second_budget(self):
        self.require_interface()
        original = proton.async_run_command
        budgets = []

        async def bounded(cmd, timeout, **kwargs):
            budgets.append(timeout)
            self.assertNotIn('synthetic-password', repr(cmd))
            self.assertNotIn('synthetic-password', repr(kwargs.get('env')))
            return await original(cmd, timeout, **kwargs)

        with patch.object(proton, 'async_run_command', side_effect=bounded):
            self.assertTrue(await self.provider.authenticate())
        self.assertEqual(budgets, [120])
        self.assertTrue(json.loads(self.session.read_text())['refreshed'])

    async def test_malformed_helper_response_is_a_fixed_error(self):
        self.require_interface()
        from unittest.mock import AsyncMock
        with patch.object(proton, 'async_run_command', new=AsyncMock(
                return_value=subprocess.CompletedProcess([], 0, '[]', 'synthetic-secret-token'))):
            with self.assertRaises(RuntimeError) as error:
                await self.provider._run_sdk_job('api', '/vpn/logicals')
        self.assertNotIn('synthetic-secret-token', str(error.exception))

    async def test_async_latency_probes_are_bounded_and_cancelled(self):
        active = 0
        peak = 0
        finished = 0

        async def probe(cmd, timeout, **kwargs):
            nonlocal active, peak, finished
            self.assertEqual(timeout, 3)
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(30)
            finally:
                active -= 1
                finished += 1

        servers = [dict(name=str(i), entry_ip='203.0.113.1') for i in range(20)]
        with patch.object(proton, 'async_run_command', side_effect=probe):
            task = asyncio.create_task(self.provider._filter_by_latency(servers))
            await asyncio.sleep(.01)
            self.assertEqual(peak, 10)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(active, 0)
        self.assertEqual(finished, 10)

    async def test_latency_preserves_reachable_fallback_and_threshold(self):
        async def probe(cmd, timeout, **kwargs):
            index = int(cmd[-1].split('.')[-1])
            return subprocess.CompletedProcess(cmd, 0, 'time=' + str(index * 10), '')

        self.provider.config._data['PROTON_MAX_LATENCY'] = '15'
        servers = [dict(name=str(i), entry_ip='203.0.113.' + str(i)) for i in (3, 2, 1)]
        with patch.object(proton, 'async_run_command', side_effect=probe):
            result = await self.provider._filter_by_latency(servers)
        self.assertEqual([s['name'] for s in result], ['1'])
