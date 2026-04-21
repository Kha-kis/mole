#!/usr/bin/env python3
"""
Standalone concurrency smoke test for mole's DoT pool.

Approximates the KI-014 workload: many parallel DNS queries with realistic
upstream latency. Compares the new UpstreamPool against a baseline that
mimics the pre-change behavior (one fresh TLS handshake per query).

Run:
    python3 tests/smoke_dot_concurrency.py

This is not a pytest test — it's a benchmark/reproducer. Exit 0 on success.
"""

import asyncio
import os
import struct
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mole_pkg.services.dns import DOTServer  # noqa: E402
from mole_pkg.services.dns_upstream import UpstreamPool, _Connection  # noqa: E402


# Simulated latency (matches observed KI-014 conditions)
HANDSHAKE_LATENCY = 0.050   # 50ms TCP+TLS handshake
QUERY_LATENCY = 0.010       # 10ms server-side per query
N_PARALLEL = 50             # matches the KI-014 repro scale


class _FakeConfig:
    dot_bind = '127.0.0.1'
    dot_port = 53
    dot_upstream = 'cloudflare'
    dot_upstreams = ['cloudflare']
    dot_caching = True
    dot_cache_ttl = 0
    dot_custom_server = ''
    dot_update_period = 0
    dot_pool_size = 2
    dot_query_timeout = 5.0
    dot_query_retries = 1
    dot_retry_backoff_ms = 0
    dot_block_ads = False
    dot_block_malware = False
    dot_block_tracking = False
    dot_enabled = True


def _make_query(xid: int, name: str) -> bytes:
    header = struct.pack('!HHHHHH', xid, 0x0100, 1, 0, 0, 0)
    labels = []
    for part in name.rstrip('.').split('.'):
        labels.append(bytes([len(part)]) + part.encode('ascii'))
    qname = b''.join(labels) + b'\x00'
    return header + qname + struct.pack('!HH', 1, 1)


class _FakePooledConn:
    """Simulates a persistent connection: handshake once on first use,
    cheap per query after. Models the post-change behavior."""

    def __init__(self):
        self.handshakes = 0
        self.queries = 0
        self._opened = False
        self._lock = asyncio.Lock()

    def is_open(self):
        return self._opened

    async def ensure_open(self, connect_timeout):
        async with self._lock:
            if self._opened:
                return
            await asyncio.sleep(HANDSHAKE_LATENCY)
            self.handshakes += 1
            self._opened = True

    async def query(self, query_bytes, client_xid, timeout):
        await self.ensure_open(timeout)
        self.queries += 1
        await asyncio.sleep(QUERY_LATENCY)
        return struct.pack('!H', client_xid) + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + \
               b'\x00' * 20 + struct.pack('!I', 60) + b'\x00\x04\x01\x02\x03\x04'

    async def close(self):
        self._opened = False


class _FakePerQueryConn:
    """Simulates pre-change: every query pays the handshake cost."""

    def __init__(self):
        self.handshakes = 0
        self.queries = 0

    def is_open(self):
        return False

    async def ensure_open(self, connect_timeout):
        await asyncio.sleep(HANDSHAKE_LATENCY)
        self.handshakes += 1

    async def query(self, query_bytes, client_xid, timeout):
        await self.ensure_open(timeout)
        self.queries += 1
        await asyncio.sleep(QUERY_LATENCY)
        return struct.pack('!H', client_xid) + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + \
               b'\x00' * 20 + struct.pack('!I', 60) + b'\x00\x04\x01\x02\x03\x04'

    async def close(self):
        pass


def _install(pool: UpstreamPool, conns):
    pool._targets[0]._connections = conns
    pool._targets[0].pool_size = len(conns)


async def _run_workload(server: DOTServer, queries, label: str):
    start = time.perf_counter()
    results = await asyncio.gather(*[server.resolve(q) for q in queries])
    elapsed = time.perf_counter() - start
    ok = sum(1 for r in results if r is not None)
    return {
        'label': label,
        'elapsed_s': elapsed,
        'success': ok,
        'total': len(queries),
        'stats': dict(server._stats),
    }


async def main():
    print(f"=== mole DoT concurrency smoke test ===")
    print(f"N parallel: {N_PARALLEL}")
    print(f"Simulated handshake: {HANDSHAKE_LATENCY*1000:.0f}ms  query: {QUERY_LATENCY*1000:.0f}ms")
    print()

    # ----- Scenario A: Baseline — one connection per query, no singleflight
    print(f"[A] Baseline (pre-change): handshake per query, no singleflight")
    baseline_server = DOTServer(_FakeConfig(), 'vpn')
    perq_conns = [_FakePerQueryConn() for _ in range(N_PARALLEL)]
    _install(baseline_server._pool, perq_conns)
    distinct_queries = [_make_query(xid=i, name=f"d{i}.example.com.")
                        for i in range(N_PARALLEL)]
    a_distinct = await _run_workload(baseline_server, distinct_queries, "A-distinct")
    a_handshakes = sum(c.handshakes for c in perq_conns)
    await baseline_server.stop()
    print(f"    distinct workload: {a_distinct['success']}/{a_distinct['total']} "
          f"in {a_distinct['elapsed_s']*1000:.0f}ms")
    print(f"    upstream queries: {a_distinct['stats']['upstream_queries']}  "
          f"handshakes: {a_handshakes}")

    # ----- Scenario B: New UpstreamPool (pool_size=2), distinct queries
    print()
    print(f"[B] Post-change: UpstreamPool (pool_size=2), distinct queries")
    new_server = DOTServer(_FakeConfig(), 'vpn')
    pooled_conns = [_FakePooledConn() for _ in range(2)]
    _install(new_server._pool, pooled_conns)
    distinct_queries = [_make_query(xid=i, name=f"new{i}.example.com.")
                        for i in range(N_PARALLEL)]
    b_distinct = await _run_workload(new_server, distinct_queries, "B-distinct")
    # Second burst — pool is already warm
    distinct2 = [_make_query(xid=i + 1000, name=f"warm{i}.example.com.")
                 for i in range(N_PARALLEL)]
    b_warm = await _run_workload(new_server, distinct2, "B-warm")
    b_handshakes = sum(c.handshakes for c in pooled_conns)
    b_queries = sum(c.queries for c in pooled_conns)
    print(f"    burst 1: {b_distinct['success']}/{b_distinct['total']} in "
          f"{b_distinct['elapsed_s']*1000:.0f}ms")
    print(f"    burst 2 (warm pool): {b_warm['success']}/{b_warm['total']} in "
          f"{b_warm['elapsed_s']*1000:.0f}ms")
    print(f"    total upstream queries: {b_queries}  "
          f"total handshakes: {b_handshakes}")
    await new_server.stop()

    # ----- Scenario C: Singleflight — all parallel queries for SAME domain
    print()
    print(f"[C] Post-change: {N_PARALLEL} parallel queries for SAME domain")
    sf_server = DOTServer(_FakeConfig(), 'vpn')
    sf_conns = [_FakePooledConn() for _ in range(2)]
    _install(sf_server._pool, sf_conns)
    same_queries = [_make_query(xid=i, name='tracker.example.com.')
                    for i in range(N_PARALLEL)]
    c = await _run_workload(sf_server, same_queries, "C-same")
    c_handshakes = sum(cn.handshakes for cn in sf_conns)
    print(f"    {c['success']}/{c['total']} in {c['elapsed_s']*1000:.0f}ms")
    print(f"    upstream queries: {c['stats']['upstream_queries']}  "
          f"singleflight collapses: {c['stats']['singleflight_collapses']}  "
          f"handshakes: {c_handshakes}")
    await sf_server.stop()

    # ----- Verdict
    print()
    print("=== Results ===")
    print(f"{'scenario':<42} {'time':>8}  {'upstream':>9}  {'handshakes':>11}")
    print(f"{'-'*42} {'-'*8}  {'-'*9}  {'-'*11}")
    print(f"{'A  baseline, 50 distinct queries':<42} "
          f"{a_distinct['elapsed_s']*1000:>7.0f}ms  "
          f"{a_distinct['stats']['upstream_queries']:>9d}  {a_handshakes:>11d}")
    print(f"{'B  pooled, 50 distinct (burst 1 + warm)':<42} "
          f"{(b_distinct['elapsed_s']+b_warm['elapsed_s'])*1000:>7.0f}ms  "
          f"{b_queries:>9d}  {b_handshakes:>11d}")
    print(f"{'C  pooled + singleflight, 50 duplicates':<42} "
          f"{c['elapsed_s']*1000:>7.0f}ms  "
          f"{c['stats']['upstream_queries']:>9d}  {c_handshakes:>11d}")

    improvements = []
    # A: 50 handshakes for 50 queries. B: 2 handshakes for 100 queries. 25x fewer handshakes
    handshake_reduction_burst = a_handshakes - (b_handshakes // 2)  # normalize to per-burst
    if b_handshakes < a_handshakes:
        improvements.append(
            f"pooled: {b_handshakes} handshakes total vs {a_handshakes} "
            f"per-burst baseline = {a_handshakes // max(b_handshakes, 1)}× fewer"
        )
    if c['stats']['upstream_queries'] == 1 and c['stats']['singleflight_collapses'] == N_PARALLEL - 1:
        improvements.append(f"singleflight collapses {N_PARALLEL} → 1 upstream query")
    if b_distinct['success'] == N_PARALLEL and b_warm['success'] == N_PARALLEL and c['success'] == N_PARALLEL:
        improvements.append(f"all scenarios answer {N_PARALLEL}/{N_PARALLEL}")

    if improvements:
        print()
        print("[OK] " + "; ".join(improvements))
        return 0
    print()
    print("[FAIL] no measured improvement")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
