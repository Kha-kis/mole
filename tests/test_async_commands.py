import asyncio
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mole_pkg import utils


class AsyncNamespaceCommands(unittest.IsolatedAsyncioTestCase):
    def launcher(self, script, pids):
        original = asyncio.create_subprocess_exec

        async def launch(*argv, **kwargs):
            self.assertEqual(argv[:4], ('ip', 'netns', 'exec', 'synthetic'))
            child = await original(sys.executable, '-c', script, **kwargs)
            pids.append(child.pid)
            return child
        return launch

    async def test_mapping_wait_keeps_heartbeat_running(self):
        self.assertTrue(callable(getattr(utils, 'async_run_in_netns', None)))
        pids, beats = [], []

        async def heartbeat():
            await asyncio.sleep(0.01)
            beats.append(time.monotonic())

        started = time.monotonic()
        with patch('asyncio.create_subprocess_exec', side_effect=self.launcher('import time; time.sleep(.15); print("done")', pids)):
            result, _ = await asyncio.gather(utils.async_run_in_netns(['synthetic'], 'synthetic', 1), heartbeat())
        self.assertEqual(result.stdout.strip(), 'done')
        self.assertLess(beats[0] - started, .12)
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)

    async def test_command_timeout_reaps_group(self):
        self.assertTrue(callable(getattr(utils, 'async_run_in_netns', None)))
        pids = []
        with patch('asyncio.create_subprocess_exec', side_effect=self.launcher('import time; time.sleep(30)', pids)):
            with self.assertRaises(asyncio.TimeoutError):
                await utils.async_run_in_netns(['synthetic'], 'synthetic', .05)
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)
        with self.assertRaises(ProcessLookupError):
            os.killpg(pids[0], 0)

    async def test_command_cancellation_reaps_group(self):
        self.assertTrue(callable(getattr(utils, 'async_run_in_netns', None)))
        pids = []
        with patch('asyncio.create_subprocess_exec', side_effect=self.launcher('import time; time.sleep(30)', pids)):
            task = asyncio.create_task(utils.async_run_in_netns(['synthetic'], 'synthetic', 10))
            while not pids:
                await asyncio.sleep(.001)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)
        with self.assertRaises(ProcessLookupError):
            os.killpg(pids[0], 0)
