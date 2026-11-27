import asyncio
from contextlib import asynccontextmanager
import os
import signal
import sys
import time
import unittest
from unittest.mock import AsyncMock, Mock, patch

from mole_pkg.validation import ExitValidator, ValidationRound, ValidationStageError
from test_validation import attempt


class CancelledProbeCleanup(unittest.IsolatedAsyncioTestCase):
    def setup_validator(self):
        gate = Mock()
        gate.remove_probe = AsyncMock()
        targets = [dict(host='api.ipify.org', path='/?format=json', ip='1.1.1.1')]
        validator = ExitValidator(Mock(netns='isolated'), gate,
                                  _resolve_targets=AsyncMock(return_value=targets))
        group = Mock()
        validator._create_cgroup = Mock(return_value=group)
        value = attempt()
        round_ = ValidationRound('c' * 64, value, time.monotonic())
        return validator, gate, group, value, round_

    async def test_cleanup_errors_do_not_replace_original_cancellation(self):
        for failure in ('rules', 'group'):
            with self.subTest(failure=failure):
                validator, gate, group, value, round_ = self.setup_validator()
                cancelled = asyncio.CancelledError()
                @asynccontextmanager
                async def child(command):
                    raise cancelled
                    yield
                if failure == 'rules':
                    gate.remove_probe.side_effect = RuntimeError('secret-rule-detail')
                else:
                    group.rmdir.side_effect = OSError('secret-group-detail')
                with patch('mole_pkg.validation.owned_child', child), \
                        patch('mole_pkg.utils.log.warning') as warning, \
                        self.assertRaises(BaseException) as caught:
                    await validator.observe(value, round_, time.monotonic() + 1)
                self.assertIs(caught.exception, cancelled)
                gate.remove_probe.assert_awaited_once_with(value, round_)
                text = ' '.join(str(call) for call in warning.call_args_list)
                self.assertIn('cleanup', text)
                self.assertNotIn('secret-', text)
                if failure == 'rules':
                    group.rmdir.assert_not_called()

    async def test_cancellation_still_finishes_successful_cleanup(self):
        validator, gate, group, value, round_ = self.setup_validator()
        cancelled = asyncio.CancelledError()
        @asynccontextmanager
        async def child(command):
            raise cancelled
            yield
        with patch('mole_pkg.validation.owned_child', child), \
                patch('mole_pkg.utils.log.warning') as warning, self.assertRaises(asyncio.CancelledError) as caught:
            await validator.observe(value, round_, time.monotonic()+1)
        self.assertIs(caught.exception, cancelled)
        gate.remove_probe.assert_awaited_once_with(value, round_)
        group.rmdir.assert_called_once()
        warning.assert_not_called()

    async def test_non_cancelled_cleanup_failure_remains_an_error(self):
        validator, gate, group, value, round_ = self.setup_validator()
        @asynccontextmanager
        async def child(command):
            raise RuntimeError('secret-admission-detail')
            yield
        gate.remove_probe.side_effect = OSError('secret-rule-detail')
        with patch('mole_pkg.validation.owned_child', child), self.assertRaises(ValidationStageError) as caught:
            await validator.observe(value, round_, time.monotonic() + 1)
        self.assertEqual(caught.exception.stage, 'cleanup')
        self.assertNotIn('secret-', str(caught.exception))
        group.rmdir.assert_not_called()

    async def test_second_cancel_during_cleanup_preserves_cancelled_outcome(self):
        validator, gate, group, value, round_ = self.setup_validator()
        started, cleaning = asyncio.Event(), asyncio.Event()
        @asynccontextmanager
        async def child(command):
            started.set()
            await asyncio.Event().wait()
            yield
        async def cleanup(*args):
            cleaning.set()
            await asyncio.Event().wait()
        gate.remove_probe.side_effect = cleanup
        with patch('mole_pkg.validation.owned_child', child):
            task = asyncio.create_task(validator.observe(value, round_, time.monotonic()+1))
            await started.wait()
            task.cancel()
            await cleaning.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        group.rmdir.assert_not_called()

    async def test_cancelled_real_helper_is_reaped_before_failed_rule_cleanup(self):
        from mole_pkg.validation import owned_child
        validator, gate, group, value, round_ = self.setup_validator()
        started = asyncio.Event()
        processes = []
        @asynccontextmanager
        async def child(command):
            async with owned_child([sys.executable, '-c', 'import time;time.sleep(30)']) as process:
                processes.append(process)
                started.set()
                yield process
        gate.remove_probe.side_effect = OSError('secret-rule-detail')
        with patch('mole_pkg.validation.owned_child', child), patch('mole_pkg.utils.log.warning'):
            task = asyncio.create_task(validator.observe(value, round_, time.monotonic()+2))
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertEqual(processes[0].returncode, -signal.SIGKILL)
        with self.assertRaises(ProcessLookupError):
            os.kill(processes[0].pid, 0)
        group.rmdir.assert_not_called()

    async def test_total_timeout_reports_cleanup_failure_without_losing_timeout(self):
        validator, gate, group, value, round_ = self.setup_validator()
        @asynccontextmanager
        async def child(command):
            await asyncio.Event().wait()
            yield
        gate.remove_probe.side_effect = OSError('secret-rule-detail')
        with patch('mole_pkg.validation.owned_child', child), \
                patch('mole_pkg.utils.log.warning'), self.assertRaises(ValidationStageError) as caught:
            await validator.validate(value, round_, Mock(), time.monotonic()+.02)
        self.assertEqual(caught.exception.stage, 'cleanup')
        self.assertNotIn('secret-', str(caught.exception))
