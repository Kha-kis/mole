import asyncio
import unittest
import subprocess
import time
from unittest.mock import AsyncMock, patch

from mole_pkg.network import ValidationGate
from mole_pkg.validation import ValidationRound
from test_validation import attempt


class ValidationGateTests(unittest.IsolatedAsyncioTestCase):
    def gate(self):
        return ValidationGate('qa-fixture', '10.200.200.0/24')

    async def test_closed_rules_cover_all_hooks_before_established_and_no_uid_bypass(self):
        gate = self.gate()
        script = gate.closed_rules()
        self.assertIn('hook output priority -150; policy drop', script)
        self.assertIn('hook input priority -150; policy drop', script)
        self.assertIn('hook forward priority -150; policy drop', script)
        self.assertNotIn('skuid', script)
        self.assertNotIn('ct state established accept', script)
        self.assertIn('meta nfproto ipv6 counter drop', script)
        self.assertNotIn('flush ruleset', script)

    async def test_round_fence_is_separate_and_grant_never_renews_it(self):
        gate = self.gate()
        value = attempt()
        round_ = ValidationRound('c' * 64, value, 10, 90)
        fence = gate.round_rules(round_)
        grant = gate.grant_rules(round_)
        self.assertIn('timeout 90s', fence)
        self.assertIn('f_' + round_.id[:24], fence)
        self.assertNotIn('add element inet mole_validation f_', grant)
        self.assertIn('@f_' + round_.id[:24], grant)
        self.assertIn('@g_' + round_.id[:24], grant)
        next_ = ValidationRound('d' * 64, value, 40, 90)
        self.assertNotEqual(gate.grant_rules(next_), grant)

    async def test_outer_transport_requires_exact_endpoint_udp_port_and_mark(self):
        script = self.gate().peer_rules(attempt())
        self.assertIn('ip daddr 8.8.8.8 udp dport 51820 meta mark 51820', script)
        self.assertNotIn('ip daddr 8.8.8.8 accept', script)

    async def test_stale_owner_is_rejected_before_a_command(self):
        gate = self.gate()
        with self.assertRaises(RuntimeError):
            await gate.authorize(attempt(), None, {})

    async def test_replacement_waits_for_cancelled_mutation_cleanup(self):
        gate = self.gate()
        value = attempt()
        gate.attempt = value
        gate.round = round_ = ValidationRound('c' * 64, value, time.monotonic(), 90)
        started, cleanup_allowed = asyncio.Event(), asyncio.Event()
        events = []
        async def mutate(script):
            if script.startswith('add element'):
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    await cleanup_allowed.wait()
                    events.append('old_drained')
            else:
                events.append('closed')
        gate._command = AsyncMock(side_effect=mutate)
        gate._verify_base = AsyncMock(return_value=[])
        evidence = dict(attempt=value.to_dict(), round_id=round_.id, allowed=True,
                        authorization_deadline=time.monotonic() + 200, transport_deadline=time.monotonic() + 200)
        with patch('mole_pkg.network.async_run_in_netns', new=AsyncMock(
                    return_value=subprocess.CompletedProcess([], 1, '', ''))):
            mutation = asyncio.create_task(gate.authorize(value, round_, evidence))
            await started.wait()
            mutation.cancel()
            replacement = asyncio.create_task(gate.quarantine(None))
            await asyncio.sleep(.01)
            self.assertEqual(events, [])
            cleanup_allowed.set()
            await asyncio.gather(mutation, return_exceptions=True)
            await replacement
        self.assertEqual(events, ['old_drained', 'closed'])
