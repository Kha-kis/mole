"""Fixed exit adapters. The observer waits for cgroup admission before sockets."""
import ctypes
import contextlib
import errno
import http.client
import json
import os
import signal
import socket
import ssl
import struct
import sys
import time

from .discovery import HEX, public_ipv4
from .dns_health import healthy_reply

ADAPTERS = {'api.ipify.org': '/?format=json', 'ifconfig.co': '/json'}
LIMIT = 65536
TRANSIENT_OBSERVATION_REASONS = frozenset(('network_timeout', 'network_unreachable'))
OBSERVATION_REASONS = TRANSIENT_OBSERVATION_REASONS | frozenset((
    'tls_failed', 'http_rejected', 'response_invalid', 'conflicting_exits', 'observer_failed'))


class ObservationFailure(ValueError):
    """A fixed reason, never a response body or underlying exception message."""
    def __init__(self, reason):
        self.reason = reason if isinstance(reason, str) and reason in OBSERVATION_REASONS else 'observer_failed'
        super().__init__(self.reason)


def validate_targets(targets):
    if not isinstance(targets, list) or not 1 <= len(targets) <= 2:
        raise ValueError('invalid probe targets')
    seen = set()
    for target in targets:
        if (not isinstance(target, dict) or set(target) != {'host', 'ip', 'path'} or
                target.get('host') not in ADAPTERS or
                target.get('path') != ADAPTERS[target['host']] or target['host'] in seen):
            raise ValueError('invalid probe adapter')
        public_ipv4(target.get('ip'))
        seen.add(target['host'])
    return targets


def parse_observations(values):
    if not values:
        raise ValueError('no exit observation')
    addresses = {public_ipv4(value.get('ip')) for value in values if isinstance(value, dict)}
    if len(addresses) != 1 or len(values) != sum(isinstance(v, dict) for v in values):
        raise ValueError('conflicting exit observations')
    return next(iter(addresses))


def resolve():
    targets = []
    for host, path in ADAPTERS.items():
        try:
            answers = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
            addresses = sorted({public_ipv4(answer[4][0]) for answer in answers})
            if addresses:
                targets.append(dict(host=host, path=path, ip=addresses[0]))
        except (OSError, ValueError):
            continue
    return validate_targets(targets)


class BoundHTTPS(http.client.HTTPSConnection):
    def __init__(self, target, timeout, *, context=None):
        self.tls_context = context if context is not None else ssl.create_default_context()
        super().__init__(target['host'], port=443, timeout=timeout, context=self.tls_context)
        self.address = target['ip']

    def connect(self):
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.timeout)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'mole\0')
            raw.connect((self.address, 443))
            self.sock = self.tls_context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


@contextlib.contextmanager
def observer_timeout(seconds):
    """The dedicated synchronous observer owns its timer, not another process."""
    if seconds <= 0:
        raise TimeoutError
    if any(signal.getitimer(signal.ITIMER_REAL)):
        raise RuntimeError('observer timer already owned')
    previous = signal.getsignal(signal.SIGALRM)
    def expired(signum, frame):
        raise TimeoutError
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _observer_remaining(connection, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    connection.timeout = remaining
    if connection.sock is not None:
        connection.sock.settimeout(remaining)
    return remaining


def observe(targets):
    validate_targets(targets)
    # Do not retain namespace/firewall administration after admission.
    if os.geteuid() == 0:
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) != 0:
        raise RuntimeError('cannot restrict observer privileges')
    # Leave time for the fixed JSON reply before the parent's ten-second cap.
    deadline = time.monotonic() + 9
    values = []
    failures = []
    for target in targets:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        adapter_deadline = min(deadline, time.monotonic() + 5)
        connection = BoundHTTPS(target, min(5, remaining))
        try:
            with observer_timeout(_observer_remaining(connection, adapter_deadline)):
                connection.request('GET', target['path'], headers={'Accept': 'application/json',
                                   'User-Agent': 'mole-exit-validation/1', 'Connection': 'close'})
                _observer_remaining(connection, adapter_deadline)
                response = connection.getresponse()
                if response.status != 200:
                    failures.append('http_rejected')
                    continue
                _observer_remaining(connection, adapter_deadline)
                data = response.read(LIMIT + 1)
                _observer_remaining(connection, adapter_deadline)
            if len(data) > LIMIT:
                raise ObservationFailure('response_invalid')
            try:
                value = json.loads(data)
                if not isinstance(value, dict):
                    raise ValueError
                public_ipv4(value.get('ip'))
            except (ValueError, TypeError):
                raise ObservationFailure('response_invalid') from None
            values.append(value)
        except ssl.SSLError:
            raise ObservationFailure('tls_failed') from None
        except (TimeoutError, socket.timeout):
            failures.append('network_timeout')
        except OSError as error:
            if isinstance(error, ConnectionError) or error.errno in (
                    errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN,
                    errno.ECONNRESET, errno.ECONNREFUSED, errno.ETIMEDOUT, errno.EPIPE):
                failures.append('network_unreachable')
            else:
                raise ObservationFailure('observer_failed') from None
        except http.client.HTTPException:
            raise ObservationFailure('response_invalid') from None
        finally:
            connection.close()
    if not values:
        reason = next((item for item in failures if item not in TRANSIENT_OBSERVATION_REASONS),
                      failures[0] if failures else 'observer_failed')
        raise ObservationFailure(reason)
    try:
        return parse_observations(values)
    except ValueError:
        raise ObservationFailure('conflicting_exits') from None


def probe_dns(request):
    servers = request.get('servers')
    port = request.get('port', 53)
    if not isinstance(servers, list) or not 1 <= len(servers) <= 3 or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('invalid resolver probe')
    import ipaddress
    for server in servers:
        address = ipaddress.IPv4Address(server)
        identifier = os.urandom(2)
        label = b'mole-health-' + os.urandom(16).hex().encode('ascii')
        question = bytes([len(label)]) + label + b'\x07example\x03com\0\0\x01\0\x01'
        query = identifier + struct.pack('!HHHHH', 0x0100, 1, 0, 0, 0) + question
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.settimeout(.7)
            try:
                connection.connect((str(address), port))
                connection.send(query)
                response = connection.recv(4096)
                if healthy_reply(response, query):
                    return {'dns_ready': True}
            except OSError:
                continue
    return {'dns_ready': False}


def main():
    request = None
    try:
        if sys.argv[1:] == ['resolve']:
            result = {'targets': resolve()}
        elif sys.argv[1:] == ['dns']:
            line = sys.stdin.buffer.readline(LIMIT + 1)
            if len(line) > LIMIT:
                raise ValueError
            result = probe_dns(json.loads(line))
        elif not sys.argv[1:]:
            # No network operation or target resolution precedes this barrier.
            print(json.dumps({'ready': True, 'pid': os.getpid()}), flush=True)
            line = sys.stdin.buffer.readline(LIMIT + 1)
            if len(line) > LIMIT:
                raise ValueError
            request = json.loads(line)
            if (not isinstance(request, dict) or any(not isinstance(request.get(key), str) or
                    not HEX.fullmatch(request[key]) for key in ('nonce', 'round_id'))):
                raise ValueError
            result = dict(exit_ip=observe(request['targets']), nonce=request['nonce'],
                          round_id=request['round_id'])
        else:
            raise ValueError
        print(json.dumps(result), flush=True)
        return 0
    except ObservationFailure as error:
        if isinstance(request, dict):
            print(json.dumps(dict(error='observation_unavailable', reason=error.reason,
                nonce=request['nonce'], round_id=request['round_id'])), flush=True)
        else:
            print(json.dumps({'error': 'observation_unavailable'}), flush=True)
        return 1
    except Exception:
        print(json.dumps({'error': 'observation_unavailable'}), flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
