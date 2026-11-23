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
from mole_pkg.config import Config
from mole_pkg.providers.proton import ProtonProvider


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

    async def test_original_provider_mapping_reproduction_keeps_heartbeat_running(self):
        original = asyncio.create_subprocess_exec
        pids, beats = [], []

        async def launch(*argv, **kwargs):
            self.assertEqual(argv[:5], ('ip', 'netns', 'exec', 'synthetic', 'natpmpc'))
            protocol = argv[8].upper()
            self.assertIn(protocol, ('UDP', 'TCP'))
            script = ('import time; time.sleep(.12); '
                      'print("Mapped public port 23456 protocol ' + protocol + ' to local port 0 lifetime 60")')
            child = await original(sys.executable, '-c', script, **kwargs)
            pids.append(child.pid)
            return child

        async def heartbeat():
            await asyncio.sleep(.01)
            beats.append(time.monotonic())

        with tempfile.TemporaryDirectory() as root:
            config = Config('/nonexistent')
            config._data.update(STATE_DIR=root, NETNS_NAME='synthetic')
            provider = ProtonProvider(config, utils.VPNState())
            started = time.monotonic()
            with patch('asyncio.create_subprocess_exec', side_effect=launch):
                result, _ = await asyncio.gather(provider.refresh_port_forward(), heartbeat())
            self.assertTrue(result)
            self.assertEqual(provider.state.port, 23456)
            self.assertLess(beats[0] - started, .1)
            self.assertGreater(time.monotonic() - started, .24)
        for pid in pids:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    async def test_cancellation_during_spawn_still_reaps_the_owned_child(self):
        original = asyncio.create_subprocess_exec
        started = asyncio.Event()
        pids = []

        async def launch(*args, **kwargs):
            started.set()
            await asyncio.sleep(.02)
            child = await original(sys.executable, '-c', 'import time; time.sleep(30)', **kwargs)
            pids.append(child.pid)
            return child

        with patch('asyncio.create_subprocess_exec', side_effect=launch):
            task = asyncio.create_task(utils.async_run_in_netns(['synthetic'], 'synthetic', 1))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        with self.assertRaises(ProcessLookupError):
            os.kill(pids[0], 0)

    async def test_timeout_kills_descendants_and_reaps_group_leader(self):
        original = asyncio.create_subprocess_exec
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root) / 'descendant'
            pids = []
            script = ('import pathlib, subprocess, sys, time; '
                      'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"],'
                      'stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); '
                      f'pathlib.Path({str(marker)!r}).write_text(str(child.pid)); time.sleep(30)')

            async def launch(*args, **kwargs):
                child = await original(sys.executable, '-c', script, **kwargs)
                pids.append(child.pid)
                return child

            with patch('asyncio.create_subprocess_exec', side_effect=launch):
                with self.assertRaises(asyncio.TimeoutError):
                    await utils.async_run_in_netns(['synthetic'], 'synthetic', .15)
            with self.assertRaises(ProcessLookupError):
                os.kill(pids[0], 0)
            descendant = int(marker.read_text())
            try:
                status = Path(f'/proc/{descendant}/stat').read_text().rpartition(')')[2].split()[0]
            except FileNotFoundError:
                pass
            else:
                self.assertEqual(status, 'Z')
