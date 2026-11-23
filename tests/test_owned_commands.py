import asyncio
import os
import sys
import time
import unittest
from unittest.mock import patch

from mole_pkg import utils


class OwnedCommands(unittest.IsolatedAsyncioTestCase):
    async def test_private_input_environment_and_heartbeat(self):
        self.assertTrue(callable(getattr(utils, 'async_run_command', None)))
        beats = []

        async def heartbeat():
            await asyncio.sleep(.01)
            beats.append(time.monotonic())

        start = time.monotonic()
        script = ('import os,sys,time; data=sys.stdin.buffer.read(); '
                  'time.sleep(.15); print(os.environ["SYNTHETIC_ENV"]+":"+data.decode())')
        result, _ = await asyncio.gather(utils.async_run_command(
            [sys.executable, '-c', script], 2,
            env=dict(os.environ, SYNTHETIC_ENV='fixture'), input_data=b'private'), heartbeat())
        self.assertEqual(result.stdout.strip(), 'fixture:private')
        self.assertLess(beats[0] - start, .12)

    async def test_blocked_input_timeout_reaps_child(self):
        self.assertTrue(callable(getattr(utils, 'async_run_command', None)))
        original, pids = asyncio.create_subprocess_exec, []

        async def launch(*argv, **kwargs):
            child = await original(*argv, **kwargs)
            pids.append(child.pid)
            return child

        start = time.monotonic()
        with patch('asyncio.create_subprocess_exec', side_effect=launch):
            with self.assertRaises(asyncio.TimeoutError):
                await utils.async_run_command(
                    [sys.executable, '-c', 'import time; time.sleep(30)'], .1,
                    input_data=b'x' * 2000000)
        self.assertLess(time.monotonic() - start, 1)
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)

    async def test_launch_counts_toward_deadline(self):
        self.assertTrue(callable(getattr(utils, 'async_run_command', None)))
        original, pids = asyncio.create_subprocess_exec, []

        async def launch(*argv, **kwargs):
            await asyncio.sleep(.08)
            child = await original(*argv, **kwargs)
            pids.append(child.pid)
            return child

        with patch('asyncio.create_subprocess_exec', side_effect=launch):
            with self.assertRaises(asyncio.TimeoutError):
                await utils.async_run_command([sys.executable, '-c', 'print("late")'], .02)
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)

    async def test_repeated_cancel_during_launch_reaps_child(self):
        self.assertTrue(callable(getattr(utils, 'async_run_command', None)))
        original, pids, started = asyncio.create_subprocess_exec, [], asyncio.Event()

        async def launch(*argv, **kwargs):
            started.set()
            await asyncio.sleep(.05)
            child = await original(*argv, **kwargs)
            pids.append(child.pid)
            return child

        with patch('asyncio.create_subprocess_exec', side_effect=launch):
            task = asyncio.create_task(utils.async_run_command(
                [sys.executable, '-c', 'import time; time.sleep(30)'], 1))
            await started.wait()
            task.cancel()
            await asyncio.sleep(.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)

    async def test_nonzero_exit_returns_captured_result(self):
        self.assertTrue(callable(getattr(utils, 'async_run_command', None)))
        result = await utils.async_run_command(
            [sys.executable, '-c', 'import sys; print("no",file=sys.stderr); sys.exit(7)'], 1)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stderr.strip(), 'no')
