import copy
import time
import unittest

from mole_pkg.validation import Attempt, ValidationRound, parse_evidence
from test_discovery import KEY


def candidate():
    return dict(name='NL#1', hostname='physical.example.com', entry_ip='8.8.8.8',
                exit_ip='9.9.9.9', public_key=KEY, port=51820, tier=2,
                features=4, load=20, country='NL')


def attempt():
    return Attempt('boot:start', 2, 'a' * 64, candidate(), 'b' * 64, time.monotonic() + 90)


class ValidationIdentity(unittest.TestCase):
    def test_attempt_is_immutable_and_copies_candidate(self):
        source = candidate()
        value = Attempt('boot:start', 2, 'a' * 64, source, 'b' * 64, time.monotonic() + 90)
        source['entry_ip'] = '1.1.1.1'
        self.assertEqual(value.to_dict()['candidate']['entry_ip'], '8.8.8.8')
        with self.assertRaises((TypeError, AttributeError)):
            value.candidate['entry_ip'] = '1.1.1.1'
        for field, bad in [('generation', True), ('nonce', 'bad'),
                           ('policy_revision', 'bad'), ('deadline', float('nan'))]:
            data = value.to_dict()
            data[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                Attempt(**data)

    def evidence(self, value, round_id):
        return dict(attempt=value.to_dict(), round_id=round_id, exit_ip='1.1.1.1',
                    policy_revision=value.policy_revision, allowed=True, asns=[13335],
                    observed_wall=1000.0, expires_wall=1120.0, reason='authorized')

    def test_evidence_binds_round_policy_exit_and_full_fence_lifetime(self):
        value = attempt()
        round_ = ValidationRound('c' * 64, value, 10.0, 90)
        data = self.evidence(value, round_.id)
        parsed = parse_evidence(data, round_, '1.1.1.1', now_wall=1000, now_mono=12,
                                transport_deadline=110)
        self.assertEqual(parsed['authorization_deadline'], 132)
        for field, invalid in [('round_id', 'd' * 64), ('allowed', 1),
                               ('policy_revision', 'e' * 64), ('exit_ip', '9.9.9.9'),
                               ('asns', [True]), ('observed_wall', 1001),
                               ('expires_wall', 1080), ('expires_wall', 1121)]:
            bad = dict(data, **{field: invalid})
            with self.subTest(field=field), self.assertRaises(ValueError):
                parse_evidence(bad, round_, '1.1.1.1', now_wall=1000, now_mono=12,
                               transport_deadline=110)
        with self.assertRaises(ValueError):
            parse_evidence(dict(data, candidate='extra identity'), round_, '1.1.1.1',
                           now_wall=1000, now_mono=12, transport_deadline=110)
        echoed = copy.deepcopy(data)
        echoed['attempt']['candidate']['load'] = 20.0
        with self.assertRaises(ValueError):
            parse_evidence(echoed, round_, '1.1.1.1', now_wall=1000, now_mono=12,
                           transport_deadline=110)
        with self.assertRaises(ValueError):
            parse_evidence(data, round_, '1.1.1.1', now_wall=1000, now_mono=12,
                           transport_deadline=99)


class RestrictedObservation(unittest.TestCase):
    def test_fixed_adapters_and_global_bootstrap_only(self):
        from mole_pkg.validation_worker import validate_targets, parse_observations
        targets = [{'host': 'api.ipify.org', 'ip': '8.8.8.8', 'path': '/?format=json'}]
        self.assertEqual(validate_targets(targets), targets)
        for changes in ({'host': 'other.example.com'}, {'ip': '127.0.0.1'}, {'path': '/redirect'}):
            with self.assertRaises(ValueError):
                validate_targets([dict(targets[0], **changes)])
        self.assertEqual(parse_observations([{'ip': '1.1.1.1'}, {'ip': '1.1.1.1'}]), '1.1.1.1')
        with self.assertRaises(ValueError):
            parse_observations([{'ip': '1.1.1.1'}, {'ip': '9.9.9.9'}])
        with self.assertRaises(ValueError):
            parse_observations([{'ip': '127.0.0.1'}])

    def test_authorizer_path_rejects_user_owned_or_symlink(self):
        import os
        import tempfile
        from pathlib import Path
        from mole_pkg.validation import trusted_executable
        self.assertEqual(trusted_executable('/usr/bin/true'), '/usr/bin/true')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'validator'
            path.write_text('#!/bin/sh\nexit 0\n')
            path.chmod(0o700)
            with self.assertRaises(ValueError):
                trusted_executable(str(path))
            path.unlink()
            path.symlink_to('/usr/bin/true')
            with self.assertRaises(ValueError):
                trusted_executable(str(path))

    def test_delegation_preflight_rejects_non_cgroup_path_before_activation(self):
        import tempfile
        from mole_pkg.validation import validate_cgroup_root
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                validate_cgroup_root(directory)


class OwnedValidatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_oversized_timeout_and_secret_stderr_are_fixed_failures(self):
        import sys
        from mole_pkg.validation import bounded_json_command
        for program in ["print('x'*70000)", "import time;time.sleep(30)",
                        "import sys;print('secret-token',file=sys.stderr);sys.exit(1)"]:
            with self.subTest(program=program), self.assertRaises(RuntimeError) as caught:
                await bounded_json_command([sys.executable, '-c', program], {}, .1)
            self.assertNotIn('secret-token', str(caught.exception))
