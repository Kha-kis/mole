import asyncio
import time
import unittest
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

from mole_pkg.validation import Attempt, AuthorizationDenied, ValidationRound, ValidationStageError
import test_validated_recovery as lifecycle_fixture
from test_validation import candidate


class ColdValidation(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        lifecycle_fixture.ValidatedLifecycle.setUp(self)
        self.mole.state.server_ip = candidate()['entry_ip']
        self.mole._validation_refresh_loop = AsyncMock()
        self.rounds = []
        self.attempts = []
        self.failures = []
        self.deadlines = []
        self.gate.verify_closed = AsyncMock(return_value=True)

        async def begin():
            self.attempt = Attempt(self.attempt.process_identity, self.mole.state.generation,
                self.attempt.nonce, candidate(), self.attempt.policy_revision,
                getattr(self.mole, '_candidate_deadline', 0) or time.monotonic()+90)
            self.mole._validation_attempt = self.attempt
            self.gate.attempt = self.attempt

        async def prepare(value):
            self.calls.append('fence')
            round_ = ValidationRound(format(len(self.rounds)+1, '064x'), value, time.monotonic())
            self.rounds.append(round_)
            return round_

        async def validate(value, round_, probe, deadline):
            self.calls.append('observe')
            self.attempts.append(value)
            self.deadlines.append(deadline)
            if self.failures:
                failure = self.failures.pop(0)
                if callable(failure):
                    return await failure()
                raise failure
            return dict(attempt=value.to_dict(), round_id=round_.id, allowed=True,
                authorization_deadline=time.monotonic()+120, transport_deadline=time.monotonic()+120)

        self.mole._begin_validated_attempt = AsyncMock(side_effect=begin)
        self.gate.prepare_round = AsyncMock(side_effect=prepare)
        self.mole._validator.validate = AsyncMock(side_effect=validate)
        self.addAsyncCleanup(self.cleanup_refresh)

    async def cleanup_refresh(self):
        task = getattr(self.mole, '_validation_task', None)
        if task:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def connect(self):
        with patch('mole_pkg.mole.read_wg_peer_key', return_value=candidate()['public_key']), \
                patch('mole_pkg.mole.async_run_in_netns', new=AsyncMock(return_value=Mock(returncode=0))), \
                patch('mole_pkg.mole.async_allow_vpn_server_ip', new=AsyncMock()):
            return await self.mole._connect_vpn(None)

    def transient(self):
        return ValidationStageError('observation', 'network_timeout')

    async def test_transient_then_success_uses_same_attempt_fresh_rounds_and_closed_readback(self):
        self.failures = [self.transient()]
        with patch('mole_pkg.mole.asyncio.sleep', new=AsyncMock()):
            self.assertTrue(await self.connect())
        self.assertEqual(len(self.attempts), 2)
        self.assertEqual(self.attempts[0], self.attempts[1])
        self.assertNotEqual(self.rounds[0].id, self.rounds[1].id)
        self.gate.verify_closed.assert_awaited_once_with(self.attempt)
        self.assertEqual(self.calls, ['fence', 'observe', 'revoke', 'fence', 'observe', 'authorize'])
        self.assertTrue(self.mole.state.gate_open)

    async def test_persistent_transient_failure_is_capped_at_three_rounds(self):
        self.failures = [self.transient() for _ in range(4)]
        with patch('mole_pkg.mole.asyncio.sleep', new=AsyncMock()):
            self.assertFalse(await self.connect())
        self.assertEqual(len(self.attempts), 3)
        self.assertEqual(self.gate.verify_closed.await_count, 2)
        self.assertNotIn('authorize', self.calls)
        self.assertFalse(self.mole.state.gate_open)
        self.mole._validation_refresh_loop.assert_not_awaited()

    async def test_terminal_failures_do_not_retry(self):
        failures = [AuthorizationDenied('private-denial'), RuntimeError('private-unknown')]
        failures += [ValidationStageError('observation', reason) for reason in (
            'tls_failed', 'response_invalid', 'conflicting_exits', 'http_rejected', 'observer_failed', 'unknown')]
        failures += [ValidationStageError(stage, 'network_timeout') for stage in (
            'cleanup', 'transport', 'authorizer', 'evidence', 'policy')]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__, reason=getattr(failure, 'reason', None)):
                self.attempts.clear()
                self.gate.verify_closed.reset_mock()
                self.failures = [failure]
                self.assertFalse(await self.connect())
                self.assertEqual(len(self.attempts), 1)
                self.gate.verify_closed.assert_not_awaited()
                self.assertFalse(self.mole.state.gate_open)

    async def test_failed_closed_readback_aborts_and_disconnects(self):
        for failure in (False, RuntimeError('private-readback')):
            with self.subTest(failure=type(failure).__name__):
                self.attempts.clear()
                self.failures = [self.transient()]
                self.gate.verify_closed = AsyncMock(return_value=False) if failure is False else AsyncMock(side_effect=failure)
                with patch('mole_pkg.mole.async_disconnect_vpn', new=AsyncMock()) as down:
                    with self.assertRaises(RuntimeError):
                        await self.connect()
                self.assertEqual(len(self.attempts), 1)
                down.assert_awaited_once()
                self.assertEqual(self.mole.state.recovery_reason, 'enforcement_unavailable')

    async def test_failed_revoke_is_not_retried_or_followed_by_another_candidate(self):
        self.failures = [self.transient()]
        self.gate.revoke.side_effect = RuntimeError('private-revoke')
        with patch('mole_pkg.mole.async_disconnect_vpn', new=AsyncMock()) as down:
            with self.assertRaises(RuntimeError):
                await self.connect()
        down.assert_awaited_once()
        self.assertEqual(len(self.attempts), 1)
        self.gate.verify_closed.assert_not_awaited()

    async def test_disconnect_timeout_after_failed_revoke_cannot_be_a_normal_retry_result(self):
        self.failures = [self.transient()]
        self.gate.revoke.side_effect = RuntimeError('private-revoke')
        with patch('mole_pkg.mole.async_disconnect_vpn', new=AsyncMock(side_effect=asyncio.TimeoutError)):
            with self.assertRaises(RuntimeError):
                await self.connect()
        self.assertEqual(self.mole.state.recovery_reason, 'enforcement_unavailable')

    async def test_repeated_cancel_during_revoke_attempts_disconnect_before_propagating(self):
        observing, revoking = asyncio.Event(), asyncio.Event()
        async def stalled():
            observing.set()
            await asyncio.Event().wait()
        async def revoke(value):
            revoking.set()
            await asyncio.Event().wait()
        self.failures = [stalled]
        self.gate.revoke = AsyncMock(side_effect=revoke)
        with patch('mole_pkg.mole.async_disconnect_vpn', new=AsyncMock()) as down:
            task = asyncio.create_task(self.connect())
            await observing.wait()
            task.cancel()
            await revoking.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        down.assert_awaited_once()
        self.assertEqual(self.mole.state.recovery_reason, 'enforcement_unavailable')

    async def test_disconnect_failure_does_not_replace_original_cancellation(self):
        self.failures = [asyncio.CancelledError()]
        self.gate.revoke.side_effect = RuntimeError('private-revoke')
        with patch('mole_pkg.mole.async_disconnect_vpn', new=AsyncMock(side_effect=RuntimeError('private-down'))):
            with self.assertRaises(asyncio.CancelledError):
                await self.connect()
        self.assertFalse(self.mole.state.gate_open)

    async def test_first_cancel_during_fallback_disconnect_is_preserved(self):
        self.failures = [self.transient()]
        self.gate.revoke.side_effect = RuntimeError('private-revoke')
        disconnecting = asyncio.Event()
        async def down(config):
            disconnecting.set()
            await asyncio.Event().wait()
        with patch('mole_pkg.mole.async_disconnect_vpn', new=AsyncMock(side_effect=down)):
            task = asyncio.create_task(self.connect())
            await disconnecting.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertFalse(self.mole.state.gate_open)

    async def test_backoff_does_not_extend_the_cold_deadline(self):
        self.failures = [self.transient()]
        started = time.monotonic()
        with patch.object(type(self.mole.config), 'vpn_ready_timeout', new_callable=PropertyMock, return_value=.03):
            self.assertFalse(await self.connect())
        self.assertEqual(len(self.attempts), 1)
        self.assertLess(time.monotonic()-started, .2)

    async def test_candidate_deadline_bounds_a_stalled_validation(self):
        async def stalled():
            await asyncio.Event().wait()
        self.failures = [stalled]
        self.mole._candidate_deadline = time.monotonic()+.03
        started = time.monotonic()
        self.assertFalse(await asyncio.wait_for(self.connect(), .2))
        self.assertLess(time.monotonic()-started, .2)
        self.assertEqual(len(self.attempts), 1)
        self.assertLessEqual(self.deadlines[0], self.mole._candidate_deadline)
        self.assertFalse(self.mole.state.gate_open)

    async def test_external_cancellation_propagates_after_revocation(self):
        started = asyncio.Event()
        async def stalled():
            started.set()
            await asyncio.Event().wait()
        self.failures = [stalled]
        task = asyncio.create_task(self.connect())
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(len(self.attempts), 1)
        self.gate.revoke.assert_awaited_once()
        self.assertFalse(self.mole.state.gate_open)

    async def test_withdrawal_during_backoff_cannot_grant(self):
        self.failures = [self.transient()]
        async def withdraw(*args):
            self.mole.provider.authorization_current = lambda value: False
        with patch('mole_pkg.mole.asyncio.sleep', new=AsyncMock(side_effect=withdraw)):
            self.assertFalse(await self.connect())
        self.assertEqual(len(self.attempts), 1)
        self.assertNotIn('authorize', self.calls)

    async def test_generation_change_during_backoff_cannot_grant(self):
        self.failures = [self.transient()]
        async def replace(*args):
            self.mole.state.generation += 1
        with patch('mole_pkg.mole.asyncio.sleep', new=AsyncMock(side_effect=replace)):
            self.assertFalse(await self.connect())
        self.assertEqual(len(self.attempts), 1)
        self.assertNotIn('authorize', self.calls)
