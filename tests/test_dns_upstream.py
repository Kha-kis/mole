"""
Tests for mole_pkg.services.dns_upstream — the connection pool, pipelining,
retry + failover logic, and DOT_PROVIDERS resolution.

These tests avoid real networking by substituting fake _Connection objects
into _UpstreamTarget._connections, so the pool's retry/failover control flow
can be exercised deterministically.
"""

import asyncio
import struct
import unittest
from unittest.mock import patch

from mole_pkg.services.dns_upstream import (
    DOT_PROVIDERS,
    UpstreamExhausted,
    UpstreamPool,
    _Connection,
    _UpstreamTarget,
    resolve_upstream,
)


# ---------- Helpers ----------

def _make_query(xid: int = 0x1234, name: str = "example.com.", qtype: int = 1) -> bytes:
    """Build a minimally valid DNS query for unit-level use."""
    header = struct.pack('!HHHHHH', xid, 0x0100, 1, 0, 0, 0)
    # Encode QNAME
    labels = []
    for part in name.rstrip('.').split('.'):
        labels.append(bytes([len(part)]) + part.encode('ascii'))
    qname = b''.join(labels) + b'\x00'
    tail = struct.pack('!HH', qtype, 1)  # QTYPE, QCLASS=IN
    return header + qname + tail


def _make_response(query: bytes, body: bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00') -> bytes:
    """Echo the xid back with a minimal answer section placeholder."""
    return query[:2] + body


class _FakeConnection:
    """Stand-in for _Connection that returns canned responses.

    Supports:
      - success with optional per-call delay
      - raising a specified exception on the first N calls ("flaky")
      - always-failing
    """

    def __init__(
        self,
        host: str = 'x',
        port: int = 853,
        sni: str = 'x',
        *,
        response_body: bytes = b'\x00' * 8,
        delay: float = 0.0,
        fail_first: int = 0,
        always_fail: bool = False,
        fail_exc: Exception = None,
    ):
        self.host = host
        self.port = port
        self.sni = sni
        self.calls = 0
        self._response_body = response_body
        self._delay = delay
        self._fail_first = fail_first
        self._always_fail = always_fail
        self._fail_exc = fail_exc or ConnectionError("fake connection down")
        self._open = True

    def is_open(self) -> bool:
        return self._open

    async def ensure_open(self, connect_timeout):
        if not self._open:
            raise self._fail_exc

    async def query(self, query_bytes, client_xid, timeout):
        self.calls += 1
        if self._always_fail:
            raise self._fail_exc
        if self.calls <= self._fail_first:
            raise self._fail_exc
        if self._delay:
            await asyncio.sleep(self._delay)
        return struct.pack('!H', client_xid) + self._response_body

    async def close(self):
        self._open = False


def _install_fake_conns(pool: UpstreamPool, factories):
    """Replace each target's connection list with FakeConnections.

    factories is a list-of-lists; factories[i][j] is the FakeConnection to
    install at pool._targets[i]._connections[j].
    """
    assert len(factories) == len(pool._targets), "factory shape must match target count"
    for target, conns in zip(pool._targets, factories):
        target._connections = list(conns)
        target.pool_size = len(conns)


# ---------- resolve_upstream ----------

class TestResolveUpstream(unittest.TestCase):
    def test_known_preset(self):
        ip, port, sni = resolve_upstream('cloudflare')
        self.assertEqual(ip, '1.1.1.1')
        self.assertEqual(port, 853)
        self.assertEqual(sni, 'cloudflare-dns.com')

    def test_unknown_falls_back_to_cloudflare(self):
        self.assertEqual(resolve_upstream('nonesuch'), DOT_PROVIDERS['cloudflare'])

    def test_custom_with_port(self):
        ip, port, sni = resolve_upstream('custom', '1.2.3.4:9999')
        self.assertEqual((ip, port, sni), ('1.2.3.4', 9999, '1.2.3.4'))

    def test_custom_default_port(self):
        ip, port, _ = resolve_upstream('custom', '10.0.0.1')
        self.assertEqual((ip, port), ('10.0.0.1', 853))


# ---------- UpstreamPool happy path ----------

class TestUpstreamPoolBasics(unittest.IsolatedAsyncioTestCase):
    async def test_single_upstream_one_query(self):
        pool = UpstreamPool(upstreams=['cloudflare'], pool_size=2)
        _install_fake_conns(pool, [[_FakeConnection(), _FakeConnection()]])
        q = _make_query(xid=0xAAAA)
        resp = await pool.query(q, client_xid=0xAAAA)
        # Response should echo our xid
        self.assertEqual(resp[:2], b'\xAA\xAA')
        self.assertEqual(pool._stats.get('upstream_queries', 0), 1)
        await pool.close()

    async def test_round_robin_across_pool(self):
        c1 = _FakeConnection()
        c2 = _FakeConnection()
        pool = UpstreamPool(upstreams=['cloudflare'], pool_size=2)
        _install_fake_conns(pool, [[c1, c2]])
        for _ in range(6):
            await pool.query(_make_query(xid=1), client_xid=1)
        # Even split expected from itertools.count round robin
        self.assertEqual(c1.calls + c2.calls, 6)
        # Each at least used once
        self.assertGreater(c1.calls, 0)
        self.assertGreater(c2.calls, 0)
        await pool.close()


# ---------- retry / failover ----------

class TestUpstreamPoolRetryFailover(unittest.IsolatedAsyncioTestCase):
    async def test_retry_succeeds_on_same_upstream(self):
        # 1st call fails, 2nd succeeds. retries=2 means 3 attempts per upstream,
        # so we stay on the same upstream and succeed.
        c = _FakeConnection(fail_first=1)
        pool = UpstreamPool(upstreams=['cloudflare'], pool_size=1,
                            query_retries=2, retry_backoff_ms=0)
        _install_fake_conns(pool, [[c]])
        resp = await pool.query(_make_query(xid=7), client_xid=7)
        self.assertEqual(resp[:2], b'\x00\x07')
        self.assertEqual(c.calls, 2)  # 1 fail + 1 success
        self.assertEqual(pool._stats['retries'], 1)
        self.assertEqual(pool._stats['upstream_errors'], 1)
        self.assertEqual(pool._stats['failovers'], 0)
        await pool.close()

    async def test_failover_rotates_to_next_upstream(self):
        # First upstream always fails, second succeeds. Pool should
        # exhaust retries on #0 then failover to #1.
        c0 = _FakeConnection(always_fail=True)
        c1 = _FakeConnection()
        pool = UpstreamPool(upstreams=['cloudflare', 'quad9'], pool_size=1,
                            query_retries=1, retry_backoff_ms=0)
        _install_fake_conns(pool, [[c0], [c1]])
        resp = await pool.query(_make_query(xid=9), client_xid=9)
        self.assertEqual(resp[:2], b'\x00\x09')
        self.assertEqual(c0.calls, 2)  # retries+1 attempts on upstream 0
        self.assertEqual(c1.calls, 1)  # first try on upstream 1 succeeds
        self.assertEqual(pool._stats['failovers'], 1)
        await pool.close()

    async def test_failover_is_per_query_not_sticky(self):
        """Next query still tries the primary first — a transient failure on
        the primary must not permanently divert traffic to a secondary."""
        # Primary fails first 2 calls (exhausts retries on query 1), then
        # succeeds on query 2. Secondary always succeeds.
        c0 = _FakeConnection(fail_first=2)
        c1 = _FakeConnection()
        pool = UpstreamPool(upstreams=['cloudflare', 'quad9'], pool_size=1,
                            query_retries=1, retry_backoff_ms=0)
        _install_fake_conns(pool, [[c0], [c1]])

        # Query 1 — primary fails (2 attempts), failover to secondary succeeds
        r1 = await pool.query(_make_query(xid=1), client_xid=1)
        self.assertEqual(r1[:2], b'\x00\x01')
        self.assertEqual(c0.calls, 2)
        self.assertEqual(c1.calls, 1)

        # Query 2 — primary now healthy, should succeed on first try on primary
        r2 = await pool.query(_make_query(xid=2), client_xid=2)
        self.assertEqual(r2[:2], b'\x00\x02')
        self.assertEqual(c0.calls, 3)  # primary got another try → success
        self.assertEqual(c1.calls, 1)  # secondary unchanged
        await pool.close()

    async def test_close_is_idempotent(self):
        pool = UpstreamPool(upstreams=['cloudflare'], pool_size=1)
        _install_fake_conns(pool, [[_FakeConnection()]])
        await pool.close()
        await pool.close()  # must not raise

    async def test_ensure_open_after_close_refuses(self):
        """ensure_open() on a closed connection must raise, not reopen."""
        from mole_pkg.services.dns_upstream import _Connection
        conn = _Connection('x', 853, 'x')
        await conn.close()
        with self.assertRaises(ConnectionError):
            await conn.ensure_open(connect_timeout=1.0)

    async def test_exhausted_when_all_fail(self):
        c0 = _FakeConnection(always_fail=True)
        c1 = _FakeConnection(always_fail=True)
        pool = UpstreamPool(upstreams=['cloudflare', 'quad9'], pool_size=1,
                            query_retries=1, retry_backoff_ms=0)
        _install_fake_conns(pool, [[c0], [c1]])
        with self.assertRaises(UpstreamExhausted):
            await pool.query(_make_query(), client_xid=1)
        await pool.close()


# ---------- _Connection xid dispatch ----------

class TestConnectionDispatch(unittest.IsolatedAsyncioTestCase):
    """Exercise _Connection directly with an injected reader/writer pair
    so we can drive out-of-order frames without real networking.
    """

    async def test_out_of_order_responses(self):
        """Two concurrent queries get the right response even when the
        upstream answers the second one first."""
        conn = _Connection('x', 853, 'x')

        # Install a reader we control; close writer as None (we'll stub writes)
        reader = asyncio.StreamReader()
        sent_frames = []

        class _FakeWriter:
            def is_closing(self):
                return False
            def write(self, data):
                sent_frames.append(data)
            async def drain(self):
                pass
            def close(self):
                pass
            async def wait_closed(self):
                pass

        conn._reader = reader
        conn._writer = _FakeWriter()
        conn._read_task = asyncio.create_task(conn._read_loop())

        # Fire two queries concurrently
        q1 = _make_query(xid=0x1111, name='a.example.com.')
        q2 = _make_query(xid=0x2222, name='b.example.com.')

        t1 = asyncio.create_task(conn.query(q1, client_xid=0x1111, timeout=5.0))
        t2 = asyncio.create_task(conn.query(q2, client_xid=0x2222, timeout=5.0))

        # Wait until both have written (pool_xids allocated) and are awaiting
        await asyncio.sleep(0)
        await asyncio.sleep(0)

        # Extract the pool_xids the pool allocated from sent frames
        # Frame layout: 2-byte length, 2-byte pool xid, rest of query
        self.assertEqual(len(sent_frames), 2)
        pool_xid_1 = struct.unpack('!H', sent_frames[0][2:4])[0]
        pool_xid_2 = struct.unpack('!H', sent_frames[1][2:4])[0]
        self.assertNotEqual(pool_xid_1, pool_xid_2)

        # Feed responses in reverse order — q2's first, then q1's
        resp2_body = b'RESP2XXX'
        resp1_body = b'RESP1YYY'
        resp2_payload = struct.pack('!H', pool_xid_2) + b'\x81\x80' + resp2_body
        resp1_payload = struct.pack('!H', pool_xid_1) + b'\x81\x80' + resp1_body
        reader.feed_data(struct.pack('!H', len(resp2_payload)) + resp2_payload)
        reader.feed_data(struct.pack('!H', len(resp1_payload)) + resp1_payload)

        r1 = await t1
        r2 = await t2

        # Each caller sees their original xid spliced back
        self.assertEqual(r1[:2], b'\x11\x11')
        self.assertEqual(r2[:2], b'\x22\x22')
        # And the correct body
        self.assertIn(b'RESP1YYY', r1)
        self.assertIn(b'RESP2XXX', r2)

        await conn.close()

    async def test_connection_failure_fails_pending(self):
        """If the upstream closes mid-flight, all pending waiters unblock."""
        conn = _Connection('x', 853, 'x')
        reader = asyncio.StreamReader()

        class _FakeWriter:
            def is_closing(self):
                return False
            def write(self, data):
                pass
            async def drain(self):
                pass
            def close(self):
                pass
            async def wait_closed(self):
                pass

        conn._reader = reader
        conn._writer = _FakeWriter()
        conn._read_task = asyncio.create_task(conn._read_loop())

        q = _make_query(xid=0x3333)
        t = asyncio.create_task(conn.query(q, client_xid=0x3333, timeout=5.0))
        await asyncio.sleep(0)

        # Simulate upstream EOF
        reader.feed_eof()

        with self.assertRaises(ConnectionError):
            await t

        await conn.close()


class TestLatencyHistogram(unittest.TestCase):
    """Per-target latency window + nearest-rank percentiles."""

    def _target(self):
        return _UpstreamTarget("test", "1.1.1.1", 853, "x", pool_size=1)

    def test_empty_returns_nones(self):
        t = self._target()
        p50, p95, p99, n = t.percentiles()
        self.assertIsNone(p50)
        self.assertIsNone(p95)
        self.assertIsNone(p99)
        self.assertEqual(n, 0)

    def test_known_distribution(self):
        t = self._target()
        # 100 samples: 1.0 .. 100.0 ms
        for i in range(1, 101):
            t.record_latency_ms(float(i))
        p50, p95, p99, n = t.percentiles()
        self.assertEqual(n, 100)
        # nearest-rank: index = (n-1)*p/100 = 49 / 94 / 98 -> values 50 / 95 / 99
        self.assertEqual(p50, 50.0)
        self.assertEqual(p95, 95.0)
        self.assertEqual(p99, 99.0)

    def test_window_eviction(self):
        from mole_pkg.services.dns_upstream import _LATENCY_WINDOW
        t = self._target()
        # Fill with 9999 (would be p99) then overflow with low values.
        # Once the high samples are evicted, percentiles must drop.
        for _ in range(_LATENCY_WINDOW):
            t.record_latency_ms(9999.0)
        _, _, p99_initial, _ = t.percentiles()
        self.assertEqual(p99_initial, 9999.0)
        for _ in range(_LATENCY_WINDOW):
            t.record_latency_ms(1.0)
        _, _, p99_after, n = t.percentiles()
        self.assertEqual(n, _LATENCY_WINDOW)
        self.assertEqual(p99_after, 1.0)


class TestPoolRecordsLatencyOnSuccessOnly(unittest.IsolatedAsyncioTestCase):
    """UpstreamPool.query() must record latency on success and NOT on failure
    (so timeouts can't drag percentiles toward the configured timeout)."""

    async def test_success_records_latency(self):
        pool = UpstreamPool(['cloudflare'], pool_size=1, query_retries=0,
                            query_timeout=2.0, retry_backoff_ms=0)
        target = pool._targets[0]

        async def fake_query(q, xid, timeout):
            await asyncio.sleep(0.005)
            return _make_response(q)

        target._connections[0].query = fake_query  # type: ignore
        await pool.query(_make_query(), client_xid=0x1234)

        _, _, _, n = target.percentiles()
        self.assertEqual(n, 1)

    async def test_failure_does_not_record(self):
        pool = UpstreamPool(['cloudflare'], pool_size=1, query_retries=0,
                            query_timeout=2.0, retry_backoff_ms=0)
        target = pool._targets[0]

        async def always_timeout(q, xid, timeout):
            raise asyncio.TimeoutError()

        target._connections[0].query = always_timeout  # type: ignore
        with self.assertRaises(UpstreamExhausted):
            await pool.query(_make_query(), client_xid=0x1234)

        _, _, _, n = target.percentiles()
        self.assertEqual(n, 0)


class TestUpstreamInfoIncludesLatency(unittest.TestCase):
    """upstream_info() must surface the new latency fields so they flow
    through dns_stats.json -> /v1/dns automatically."""

    def test_keys_present(self):
        pool = UpstreamPool(['cloudflare'], pool_size=1)
        info = pool.upstream_info()
        self.assertEqual(len(info), 1)
        for key in ('query_p50_ms', 'query_p95_ms', 'query_p99_ms', 'query_samples'):
            self.assertIn(key, info[0])
        # Empty histogram -> nulls + zero count
        self.assertIsNone(info[0]['query_p50_ms'])
        self.assertEqual(info[0]['query_samples'], 0)


class TestPerUpstreamCounters(unittest.IsolatedAsyncioTestCase):
    """Per-upstream counter dict tells you which specific upstream is degrading
    when a multi-upstream failover list is configured. Aggregate counters in
    UpstreamPool._stats stay unchanged — sum-of-per-upstream == aggregate."""

    def _info_by_name(self, info):
        return {u['name']: u for u in info}

    async def test_counters_initialized_to_zero(self):
        pool = UpstreamPool(['cloudflare'], pool_size=1)
        info = pool.upstream_info()
        self.assertEqual(info[0]['counters'],
                         {'queries': 0, 'errors': 0, 'retries': 0,
                          'failovers_out': 0})

    async def test_single_upstream_success_increments_queries_only(self):
        pool = UpstreamPool(['cloudflare'], pool_size=1, query_retries=0,
                            query_timeout=2.0, retry_backoff_ms=0)
        target = pool._targets[0]

        async def ok(q, xid, timeout):
            return _make_response(q)
        target._connections[0].query = ok  # type: ignore

        await pool.query(_make_query(), client_xid=0x1)
        await pool.query(_make_query(), client_xid=0x2)

        info = pool.upstream_info()[0]
        self.assertEqual(info['counters']['queries'], 2)
        self.assertEqual(info['counters']['errors'], 0)
        self.assertEqual(info['counters']['retries'], 0)
        self.assertEqual(info['counters']['failovers_out'], 0)

    async def test_failover_counters_attribute_correctly(self):
        """Two upstreams; primary always fails; secondary always succeeds.
        After 5 queries: primary has 5 errors + 5 failovers_out; secondary
        has 5 successful queries + 0 errors + 0 failovers_out."""
        pool = UpstreamPool(['cloudflare', 'quad9'], pool_size=1,
                            query_retries=0, query_timeout=2.0,
                            retry_backoff_ms=0)
        primary, secondary = pool._targets

        async def fail(q, xid, timeout):
            raise asyncio.TimeoutError()
        async def ok(q, xid, timeout):
            return _make_response(q)
        primary._connections[0].query = fail  # type: ignore
        secondary._connections[0].query = ok  # type: ignore

        for i in range(5):
            await pool.query(_make_query(xid=i), client_xid=i)

        info = self._info_by_name(pool.upstream_info())
        self.assertEqual(info['cloudflare']['counters']['queries'], 5)
        self.assertEqual(info['cloudflare']['counters']['errors'], 5)
        self.assertEqual(info['cloudflare']['counters']['failovers_out'], 5)
        self.assertEqual(info['quad9']['counters']['queries'], 5)
        self.assertEqual(info['quad9']['counters']['errors'], 0)
        # The secondary never has anywhere to fail-over TO, so this is 0
        # even though it serves all the traffic.
        self.assertEqual(info['quad9']['counters']['failovers_out'], 0)

        # Aggregate sanity: pool._stats.upstream_queries should equal the
        # sum of per-upstream queries.
        self.assertEqual(
            pool._stats['upstream_queries'],
            sum(u['counters']['queries'] for u in pool.upstream_info()),
        )

    async def test_retries_count_per_upstream(self):
        """One upstream, query_retries=2, always fails. Expect:
        queries=3 (1 initial + 2 retries), errors=3, retries=2."""
        pool = UpstreamPool(['cloudflare'], pool_size=1, query_retries=2,
                            query_timeout=2.0, retry_backoff_ms=0)
        target = pool._targets[0]

        async def fail(q, xid, timeout):
            raise asyncio.TimeoutError()
        target._connections[0].query = fail  # type: ignore

        with self.assertRaises(UpstreamExhausted):
            await pool.query(_make_query(), client_xid=0x1)

        c = pool.upstream_info()[0]['counters']
        self.assertEqual(c['queries'], 3)
        self.assertEqual(c['errors'], 3)
        self.assertEqual(c['retries'], 2)
        self.assertEqual(c['failovers_out'], 0)


if __name__ == '__main__':
    unittest.main()
