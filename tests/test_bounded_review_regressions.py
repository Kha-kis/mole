import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import test_proton_worker as worker_fixtures
import test_recovery_orchestration as recovery_fixtures
from mole_pkg import utils


class CancellationAfterTimeout(unittest.IsolatedAsyncioTestCase):
    async def test_cancellation_during_timed_out_spawn_cannot_continue_recovery(self):
        original = asyncio.create_subprocess_exec
        started = asyncio.Event()
        pids, attempts = [], []

        async def slow_spawn(*cmd, **kwargs):
            started.set()
            await asyncio.sleep(.08)
            child = await original(*cmd, **kwargs)
            pids.append(child.pid)
            return child

        async def recovery():
            for attempt in range(2):
                attempts.append(attempt)
                try:
                    await utils.async_run_command(
                        [sys.executable, '-c', 'import time; time.sleep(30)'], .01)
                except asyncio.TimeoutError:
                    continue

        with patch('asyncio.create_subprocess_exec', side_effect=slow_spawn):
            task = asyncio.create_task(recovery())
            await started.wait()
            await asyncio.sleep(.03)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(attempts, [0])
        for pid in pids:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


class QueuedSdkGeneration(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        worker_fixtures.ProtonWorkers.setUp(self)

    async def test_job_queued_before_generation_change_cannot_start_or_adopt(self):
        self.provider._sdk_lock = asyncio.Lock()
        await self.provider._sdk_lock.acquire()
        task = asyncio.create_task(self.provider._run_sdk_job('api', '/vpn/logicals'))
        await asyncio.sleep(0)
        self.provider.state.generation += 1
        self.session.write_text('{"newer":true}')
        self.provider._sdk_lock.release()
        with self.assertRaises(RuntimeError):
            await task
        self.assertEqual(self.session.read_text(), '{"newer":true}')
        self.assertEqual(list(self.path.glob('.proton-job-*')), [])


class InstalledRecoveryTarget(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        recovery_fixtures.RecoveryOrchestration.setUp(self)

    async def test_mapping_repair_uses_installed_identity_after_rejected_candidate(self):
        self.assertTrue(await self.mole._full_renewal())
        self.config._data['PORT_FORWARD'] = 'true'
        self.mole.provider._select(self.servers[2])
        self.mole.provider.record_server_failure('preparation')
        registered = []

        async def register():
            registered.append(self.mole.provider._selected_server['entry_ip'])
            return True

        async def mapping():
            self.mole.state.forwarding_ready = True
            return True

        self.mole.provider.register_wireguard.side_effect = register
        self.mole.provider.setup_port_forward.side_effect = mapping
        self.assertTrue(await self.mole._full_renewal(reason='mapping'))
        self.assertEqual(registered, ['192.0.2.1'])
        self.assertEqual(self.mole.state.server_ip, '192.0.2.1')

    async def test_successful_verified_switch_persists_server_preference(self):
        saved = Path(self.root.name) / 'server_name'
        saved.write_text('XX#1')
        self.assertTrue(await self.mole._full_renewal())
        self.mole.provider._select(self.servers[1])
        self.assertTrue(await self.mole._attempt_selected_server('192.0.2.1'))
        self.assertEqual(self.mole.state.server_ip, '192.0.2.2')
        self.assertEqual(saved.read_text(), 'XX#2')
