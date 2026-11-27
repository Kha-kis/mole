import errno
import json
import ssl
import signal
import time
import unittest
from unittest.mock import Mock, patch

from mole_pkg import validation_worker as worker
from mole_pkg.validation import ValidationRound, ValidationStageError
from test_validation import attempt


TARGETS = [dict(host=host, path=path, ip=address) for (host, path), address in zip(
    worker.ADAPTERS.items(), ('1.1.1.1', '9.9.9.9'))]


class ObservationFailures(unittest.TestCase):
    def observe(self, outcomes):
        connections = []
        for outcome in outcomes:
            connection = Mock()
            if isinstance(outcome, Exception):
                connection.request.side_effect = outcome
            else:
                response = connection.getresponse.return_value
                response.status = 200
                response.read.return_value = outcome
            connections.append(connection)
        with patch.object(worker, 'BoundHTTPS', side_effect=connections), \
                patch.object(worker.os, 'geteuid', return_value=65534), \
                patch.object(worker.ctypes, 'CDLL') as library:
            library.return_value.prctl.return_value = 0
            return worker.observe(TARGETS[:len(outcomes)])

    def test_transient_socket_failures_are_typed_without_message_content(self):
        for error, reason in ((TimeoutError('private-timeout'), 'network_timeout'),
                              (ConnectionResetError('private-reset'), 'network_unreachable'),
                              (OSError(errno.ENETUNREACH, 'private-route'), 'network_unreachable')):
            with self.subTest(reason=reason), self.assertRaises(ValueError) as caught:
                self.observe([error, error])
            self.assertEqual(getattr(caught.exception, 'reason', None), reason)
            self.assertNotIn('private-', str(caught.exception))

    def test_one_transient_adapter_failure_still_accepts_the_other(self):
        self.assertEqual(self.observe([TimeoutError(), b'{"ip":"1.1.1.1"}']), '1.1.1.1')

    def test_two_socket_timeouts_leave_room_for_typed_reply_before_parent_timeout(self):
        clock = [0.0]
        budgets = []
        def connection(target, timeout):
            budgets.append(timeout)
            result = Mock()
            def fail(*args, **kwargs):
                clock[0] += timeout
                raise TimeoutError
            result.request.side_effect = fail
            return result
        with patch.object(worker, 'BoundHTTPS', side_effect=connection), \
                patch.object(worker.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(worker.os, 'geteuid', return_value=65534), \
                patch.object(worker.ctypes, 'CDLL') as library:
            library.return_value.prctl.return_value = 0
            with self.assertRaises(ValueError) as caught:
                worker.observe(TARGETS)
        self.assertEqual(caught.exception.reason, 'network_timeout')
        self.assertEqual(len(budgets), 2)
        self.assertLess(clock[0], 10)

    def test_request_headers_and_body_share_the_absolute_adapter_deadline(self):
        clock = [0.0]
        connection = Mock()
        def request(*args, **kwargs):
            clock[0] += 4.5
        def headers():
            clock[0] += 4.5
            return response
        def body(*args):
            clock[0] += 5
            raise TimeoutError
        response = Mock(status=200)
        response.read.side_effect = body
        connection.request.side_effect = request
        connection.getresponse.side_effect = headers
        with patch.object(worker, 'BoundHTTPS', return_value=connection), \
                patch.object(worker.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(worker.os, 'geteuid', return_value=65534), \
                patch.object(worker.ctypes, 'CDLL') as library:
            library.return_value.prctl.return_value = 0
            with self.assertRaises(ValueError) as caught:
                worker.observe(TARGETS[:1])
        self.assertEqual(caught.exception.reason, 'network_timeout')
        self.assertLess(clock[0], 10)
        response.read.assert_not_called()

    def test_observer_alarm_bounds_a_single_slow_operation_and_restores_handler(self):
        from mole_pkg.validation_worker import observer_timeout
        original = signal.getsignal(signal.SIGALRM)
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            with observer_timeout(.02):
                time.sleep(1)
        self.assertLess(time.monotonic()-started, .2)
        self.assertEqual(signal.getsignal(signal.SIGALRM), original)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_observer_alarm_does_not_replace_an_existing_timer(self):
        from mole_pkg.validation_worker import observer_timeout
        original = signal.getsignal(signal.SIGALRM)
        def handler(signum, frame):
            pass
        signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, 1)
        try:
            with self.assertRaises(RuntimeError):
                with observer_timeout(.02):
                    self.fail('must not replace a timer owned by another operation')
            self.assertIs(signal.getsignal(signal.SIGALRM), handler)
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, original)

    def test_tls_failure_is_terminal_not_a_transient_or_other_adapter_fallback(self):
        with self.assertRaises(ValueError) as caught:
            self.observe([ssl.SSLCertVerificationError('private-certificate'), b'{"ip":"1.1.1.1"}'])
        self.assertEqual(getattr(caught.exception, 'reason', None), 'tls_failed')
        self.assertNotIn('private-', str(caught.exception))

    def test_malformed_oversized_private_and_non_object_replies_are_terminal(self):
        for data in (b'private-invalid-json', b'[]', b'{"ip":"127.0.0.1"}', b'x' * (worker.LIMIT+1)):
            with self.subTest(size=len(data)), self.assertRaises(ValueError) as caught:
                self.observe([data, b'{"ip":"1.1.1.1"}'])
            self.assertEqual(getattr(caught.exception, 'reason', None), 'response_invalid')
            self.assertNotIn('private-', str(caught.exception))

    def test_conflicting_successes_are_terminal(self):
        with self.assertRaises(ValueError) as caught:
            self.observe([b'{"ip":"1.1.1.1"}', b'{"ip":"9.9.9.9"}'])
        self.assertEqual(getattr(caught.exception, 'reason', None), 'conflicting_exits')

    def test_permission_failure_is_not_retried_as_a_network_failure(self):
        with self.assertRaises(ValueError) as caught:
            self.observe([PermissionError('private-permission')])
        self.assertEqual(getattr(caught.exception, 'reason', None), 'observer_failed')

    def test_http_rejection_is_not_transient_if_no_adapter_succeeds(self):
        connection = Mock()
        connection.getresponse.return_value.status = 403
        with patch.object(worker, 'BoundHTTPS', return_value=connection), \
                patch.object(worker.os, 'geteuid', return_value=65534), \
                patch.object(worker.ctypes, 'CDLL') as library:
            library.return_value.prctl.return_value = 0
            with self.assertRaises(ValueError) as caught:
                worker.observe(TARGETS)
        self.assertEqual(getattr(caught.exception, 'reason', None), 'http_rejected')

    def test_worker_error_reply_echoes_request_identity_without_raw_details(self):
        request = dict(targets=TARGETS, nonce='a'*64, round_id='c'*64)
        from io import StringIO
        stdin = Mock(buffer=Mock(readline=Mock(return_value=json.dumps(request).encode()+b'\n')))
        # Use the real typed worker error once available, rather than a dynamic exception.
        error_class = getattr(worker, 'ObservationFailure', ValueError)
        output = StringIO()
        with patch.object(worker, 'observe', side_effect=error_class('network_timeout')), \
                patch.object(worker.sys, 'stdin', stdin), patch.object(worker.sys, 'stdout', output), \
                patch.object(worker.sys, 'argv', ['observer']):
            self.assertEqual(worker.main(), 1)
        reply = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(reply, dict(error='observation_unavailable', reason='network_timeout',
                                     nonce=request['nonce'], round_id=request['round_id']))


class ObservationReplyContract(unittest.TestCase):
    def parse(self, reply, returncode):
        from mole_pkg.validation import parse_observation_reply
        return parse_observation_reply(reply, returncode, self.value, self.round)

    def setUp(self):
        self.value = attempt()
        self.round = ValidationRound('c'*64, self.value, 1)

    def test_only_allowlisted_identity_bound_nonzero_failure_can_be_transient(self):
        reply = dict(error='observation_unavailable', reason='network_timeout',
                     nonce=self.value.nonce, round_id=self.round.id)
        for changes in ({}, {'reason': 'private-injected'}, {'round_id': 'd'*64},
                        {'nonce': 'e'*64}, {'extra': 'private-field'}):
            with self.subTest(changes=changes), self.assertRaises(ValidationStageError) as caught:
                self.parse(dict(reply, **changes), 1)
            self.assertEqual(caught.exception.retryable, not changes)
            self.assertNotIn('private-', str(caught.exception))
        with self.assertRaises(ValidationStageError) as caught:
            self.parse(reply, 0)
        self.assertFalse(caught.exception.retryable)

    def test_success_is_identity_bound_and_unknown_reasons_are_not_printed(self):
        reply = dict(exit_ip='1.1.1.1', nonce=self.value.nonce, round_id=self.round.id)
        self.assertEqual(self.parse(reply, 0), '1.1.1.1')
        with self.assertRaises(ValidationStageError):
            self.parse(dict(reply, nonce='e'*64), 0)
        with self.assertRaises(ValidationStageError):
            self.parse(reply, 1)
        error = ValidationStageError('observation', 'private-unknown-reason')
        self.assertFalse(error.retryable)
        self.assertIsNone(error.reason)
        self.assertNotIn('private-', str(error))
