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
