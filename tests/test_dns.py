"""
Tests for mole_pkg.services.dns module - DNS over TLS service
"""

import asyncio
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from mole_pkg.services.dns import (
    DOTServer,
    DOT_PROVIDERS,
)
from mole_pkg.services.dns_main import _stats_writer_loop
from mole_pkg.services.dns_upstream import UpstreamExhausted


class TestDOTProviders(unittest.TestCase):
    """Test DNS over TLS provider configuration"""

    def test_providers_exist(self):
        """DOT_PROVIDERS has expected providers"""
        self.assertIn('cloudflare', DOT_PROVIDERS)
        self.assertIn('google', DOT_PROVIDERS)
        self.assertIn('quad9', DOT_PROVIDERS)

    def test_provider_structure(self):
        """Each provider has required fields (tuple of ip, port, sni)"""
        for name, config in DOT_PROVIDERS.items():
            # DOT_PROVIDERS is a dict of tuples: (ip, port, sni_hostname)
            self.assertIsInstance(config, tuple, f"{name} should be a tuple")
            self.assertEqual(len(config), 3, f"{name} should have 3 elements")

    def test_cloudflare_config(self):
        """Cloudflare DNS config is correct"""
        cf = DOT_PROVIDERS['cloudflare']
        self.assertEqual(cf[0], '1.1.1.1')  # IP
        self.assertEqual(cf[1], 853)        # Port
        self.assertEqual(cf[2], 'cloudflare-dns.com')  # SNI

    def test_google_config(self):
        """Google DNS config is correct"""
        google = DOT_PROVIDERS['google']
        self.assertEqual(google[0], '8.8.8.8')  # IP
        self.assertEqual(google[1], 853)        # Port
        self.assertEqual(google[2], 'dns.google')  # SNI


class TestDOTServerInit(unittest.TestCase):
    """Test DOTServer initialization"""

    def _create_mock_config(self):
        """Create a mock config with default values"""
        mock_config = MagicMock()
        mock_config.dot_bind = '127.0.0.1'
        mock_config.dot_port = 53
        mock_config.dot_upstream = 'cloudflare'
        mock_config.dot_caching = True
        mock_config.dot_cache_ttl = 300
        mock_config.dot_custom_server = ''
        mock_config.block_ads = False
        mock_config.block_malware = False
        mock_config.block_tracking = False
        mock_config.dot_block_ads = False
        mock_config.dot_block_malware = False
        mock_config.dot_block_tracking = False
        mock_config.dot_update_period = 86400
        return mock_config

    def test_init_defaults(self):
        """DOTServer initializes with config"""
        mock_config = self._create_mock_config()
        server = DOTServer(mock_config, 'vpn')

        self.assertEqual(server.bind, '127.0.0.1')
        self.assertEqual(server.port, 53)
        self.assertEqual(server.netns, 'vpn')

    def test_init_custom_bind(self):
        """DOTServer accepts custom bind address"""
        mock_config = self._create_mock_config()
        mock_config.dot_bind = '0.0.0.0'
        mock_config.dot_port = 5353

        server = DOTServer(mock_config, 'vpn')

        self.assertEqual(server.bind, '0.0.0.0')
        self.assertEqual(server.port, 5353)

    def test_init_with_google_upstream(self):
        """DOTServer uses google upstream"""
        mock_config = self._create_mock_config()
        mock_config.dot_upstream = 'google'

        server = DOTServer(mock_config, 'vpn')

        self.assertEqual(server.upstream_ip, '8.8.8.8')


class TestDOTServerCache(unittest.TestCase):
    """Test DOTServer caching functionality"""

    def _create_mock_config(self, caching=True):
        mock_config = MagicMock()
        mock_config.dot_bind = '127.0.0.1'
        mock_config.dot_port = 53
        mock_config.dot_upstream = 'cloudflare'
        mock_config.dot_caching = caching
        mock_config.dot_cache_ttl = 300
        mock_config.dot_custom_server = ''
        mock_config.dot_update_period = 0
        return mock_config

    def test_cache_initialization(self):
        """Cache is initialized as empty dict"""
        mock_config = self._create_mock_config(caching=True)
        server = DOTServer(mock_config, 'vpn')
        self.assertEqual(server._cache, {})

    def test_cache_disabled(self):
        """Cache operations work when disabled"""
        mock_config = self._create_mock_config(caching=False)
        server = DOTServer(mock_config, 'vpn')
        self.assertFalse(server._cache_enabled)


class TestDOTServerBlocklist(unittest.TestCase):
    """Test DOTServer blocklist functionality"""

    def _create_mock_config(self):
        mock_config = MagicMock()
        mock_config.dot_bind = '127.0.0.1'
        mock_config.dot_port = 53
        mock_config.dot_upstream = 'cloudflare'
        mock_config.dot_caching = True
        mock_config.dot_cache_ttl = 300
        mock_config.dot_custom_server = ''
        mock_config.dot_update_period = 0
        return mock_config

    def test_blocklist_initialization(self):
        """Blocklist is initialized as empty set"""
        mock_config = self._create_mock_config()
        server = DOTServer(mock_config, 'vpn')
        self.assertEqual(server.blocked_domains, set())

    def test_blocked_domains_add(self):
        """Can add domains to blocklist"""
        mock_config = self._create_mock_config()
        server = DOTServer(mock_config, 'vpn')
        server.blocked_domains.add('blocked.com')
        self.assertIn('blocked.com', server.blocked_domains)


class TestDOTServerUpstream(unittest.TestCase):
    """Test DOTServer upstream configuration"""

    def _create_mock_config(self, upstream='cloudflare'):
        mock_config = MagicMock()
        mock_config.dot_bind = '127.0.0.1'
        mock_config.dot_port = 53
        mock_config.dot_upstream = upstream
        mock_config.dot_caching = True
        mock_config.dot_cache_ttl = 300
        mock_config.dot_custom_server = '1.2.3.4:853'
        mock_config.dot_update_period = 0
        return mock_config

    def test_get_upstream_cloudflare(self):
        """Server uses correct upstream for cloudflare"""
        mock_config = self._create_mock_config('cloudflare')
        server = DOTServer(mock_config, 'vpn')
        self.assertEqual(server.upstream_ip, '1.1.1.1')
        self.assertEqual(server.upstream_port, 853)

    def test_get_upstream_google(self):
        """Server uses correct upstream for google"""
        mock_config = self._create_mock_config('google')
        server = DOTServer(mock_config, 'vpn')
        self.assertEqual(server.upstream_ip, '8.8.8.8')

    def test_get_upstream_quad9(self):
        """Server uses correct upstream for quad9"""
        mock_config = self._create_mock_config('quad9')
        server = DOTServer(mock_config, 'vpn')
        self.assertEqual(server.upstream_ip, '9.9.9.9')

    def test_custom_upstream(self):
        """Server accepts custom upstream server"""
        mock_config = self._create_mock_config('custom')
        server = DOTServer(mock_config, 'vpn')
        self.assertEqual(server.upstream_ip, '1.2.3.4')
        self.assertEqual(server.upstream_port, 853)


class TestDOTServerAsync(unittest.TestCase):
    """Test DOTServer async operations"""

    def _create_mock_config(self):
        mock_config = MagicMock()
        mock_config.dot_bind = '127.0.0.1'
        mock_config.dot_port = 53
        mock_config.dot_upstream = 'cloudflare'
        mock_config.dot_caching = True
        mock_config.dot_cache_ttl = 300
        mock_config.dot_custom_server = ''
        mock_config.dot_update_period = 0
        return mock_config

    def test_server_not_started(self):
        """Server is not started initially"""
        mock_config = self._create_mock_config()
        server = DOTServer(mock_config, 'vpn')
        self.assertIsNone(server._transport)
        self.assertIsNone(server._protocol)


class TestDOTProvidersValues(unittest.TestCase):
    """Additional tests for DOT_PROVIDERS values"""

    def test_all_providers_have_valid_port(self):
        """All providers use port 853"""
        for name, config in DOT_PROVIDERS.items():
            self.assertEqual(config[1], 853, f"{name} should use port 853")

    def test_all_providers_have_ip(self):
        """All providers have valid IP addresses"""
        for name, config in DOT_PROVIDERS.items():
            ip = config[0]
            parts = ip.split('.')
            self.assertEqual(len(parts), 4, f"{name} IP should have 4 octets")

    def test_all_providers_have_sni(self):
        """All providers have SNI hostname"""
        for name, config in DOT_PROVIDERS.items():
            sni = config[2]
            self.assertIsInstance(sni, str)
            self.assertGreater(len(sni), 0, f"{name} should have SNI hostname")


def _make_query(xid: int = 0x1234, name: str = "example.com.", qtype: int = 1) -> bytes:
    """Build a minimally valid DNS query for resolve() tests."""
    header = struct.pack('!HHHHHH', xid, 0x0100, 1, 0, 0, 0)
    labels = []
    for part in name.rstrip('.').split('.'):
        labels.append(bytes([len(part)]) + part.encode('ascii'))
    qname = b''.join(labels) + b'\x00'
    tail = struct.pack('!HH', qtype, 1)
    return header + qname + tail


class TestDOTServerResolve(unittest.IsolatedAsyncioTestCase):
    """End-to-end resolve() tests with the upstream pool mocked."""

    def _make_config(self):
        cfg = MagicMock()
        cfg.dot_bind = '127.0.0.1'
        cfg.dot_port = 53
        cfg.dot_upstream = 'cloudflare'
        cfg.dot_upstreams = ['cloudflare']
        cfg.dot_caching = True
        cfg.dot_cache_ttl = 0
        cfg.dot_custom_server = ''
        cfg.dot_update_period = 0
        cfg.dot_pool_size = 1
        cfg.dot_query_timeout = 2.0
        cfg.dot_query_retries = 0
        cfg.dot_retry_backoff_ms = 0
        cfg.dot_block_ads = False
        cfg.dot_block_malware = False
        cfg.dot_block_tracking = False
        cfg.dot_enabled = True
        return cfg

    async def test_singleflight_collapses_concurrent_queries(self):
        """10 concurrent identical queries → 1 upstream call, 9 collapses."""
        server = DOTServer(self._make_config(), 'vpn')

        call_count = 0
        start = asyncio.Event()

        async def slow_upstream(query_bytes, client_xid):
            nonlocal call_count
            call_count += 1
            await start.wait()  # Hold all calls until we release
            # Echo client xid on a minimal valid response
            return struct.pack('!H', client_xid) + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'

        server._pool.query = slow_upstream  # type: ignore

        # Fire 10 concurrent resolves, then release
        q = _make_query(xid=0x9999, name='tracker.example.com.')
        tasks = [asyncio.create_task(server.resolve(q)) for _ in range(10)]
        await asyncio.sleep(0)  # let them all reach singleflight
        start.set()
        results = await asyncio.gather(*tasks)

        # Only one upstream call despite 10 resolves
        self.assertEqual(call_count, 1)
        # 9 collapses (leader + 9 followers = 10 total resolves)
        self.assertEqual(server._stats['singleflight_collapses'], 9)
        # cache_misses is per-query (matches dnsmasq convention): every resolve
        # that didn't find the entry in cache counts, including followers.
        self.assertEqual(server._stats['cache_misses'], 10)
        self.assertEqual(server._stats['queries_total'], 10)
        # All callers get a response (xid-spliced, but we didn't vary xid)
        self.assertTrue(all(r is not None for r in results))

        await server.stop()

    async def test_cache_hit_short_circuits_upstream(self):
        server = DOTServer(self._make_config(), 'vpn')
        calls = 0

        async def count_upstream(query_bytes, client_xid):
            nonlocal calls
            calls += 1
            return struct.pack('!H', client_xid) + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + \
                   b'\x00' * 20 + struct.pack('!I', 300) + b'\x00\x04\x01\x02\x03\x04'

        server._pool.query = count_upstream  # type: ignore

        q = _make_query(xid=0x0001, name='cached.example.com.')
        # First miss populates cache
        r1 = await server.resolve(q)
        self.assertIsNotNone(r1)
        self.assertEqual(calls, 1)
        # Second hits cache
        q2 = _make_query(xid=0x0002, name='cached.example.com.')
        r2 = await server.resolve(q2)
        self.assertIsNotNone(r2)
        self.assertEqual(calls, 1)
        self.assertEqual(server._stats['cache_hits'], 1)
        # Second caller's xid preserved
        self.assertEqual(r2[:2], b'\x00\x02')

        await server.stop()

    async def test_upstream_exhaustion_returns_none(self):
        server = DOTServer(self._make_config(), 'vpn')

        async def always_exhaust(q, xid):
            raise UpstreamExhausted("mock")

        server._pool.query = always_exhaust  # type: ignore
        r = await server.resolve(_make_query())
        self.assertIsNone(r)
        self.assertEqual(server._stats['resolve_errors'], 1)

        await server.stop()

    async def test_stats_counters_structure(self):
        """Ensure get_stats exposes the expected counter shape."""
        server = DOTServer(self._make_config(), 'vpn')
        stats = server.get_stats()
        self.assertIn('counters', stats)
        self.assertIn('upstreams', stats)
        for key in ('queries_total', 'cache_hits', 'cache_misses',
                    'singleflight_collapses', 'upstream_queries',
                    'upstream_errors', 'retries', 'failovers'):
            self.assertIn(key, stats['counters'], f"missing counter: {key}")
        # upstream_info has an entry per configured upstream
        self.assertEqual(len(stats['upstreams']), 1)
        self.assertEqual(stats['upstreams'][0]['host'], '1.1.1.1')
        await server.stop()

    async def test_singleflight_does_not_collapse_different_qclass(self):
        """IN and CH queries for the same name+qtype are DIFFERENT questions
        and must not collapse onto the same upstream query."""
        server = DOTServer(self._make_config(), 'vpn')
        call_count = 0

        async def slow_upstream(query_bytes, client_xid):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.01)
            return struct.pack('!H', client_xid) + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'

        server._pool.query = slow_upstream  # type: ignore

        # Build two queries that differ ONLY in qclass (bytes at the tail)
        q_in = _make_query(xid=0x1111, name='version.bind.')
        # Replace the last 2 bytes (qclass) with CH (=3)
        q_ch = q_in[:-2] + struct.pack('!H', 3)

        r1, r2 = await asyncio.gather(server.resolve(q_in), server.resolve(q_ch))
        # Both succeed but each hits upstream independently — no collapse
        self.assertIsNotNone(r1)
        self.assertIsNotNone(r2)
        self.assertEqual(call_count, 2)
        self.assertEqual(server._stats['singleflight_collapses'], 0)
        await server.stop()

    async def test_cache_disabled_does_not_count_misses(self):
        """With caching off, cache_misses must stay at 0 (hit rate would
        otherwise be a meaningless 0 / N)."""
        cfg = self._make_config()
        cfg.dot_caching = False
        server = DOTServer(cfg, 'vpn')

        async def ok_upstream(q, xid):
            return struct.pack('!H', xid) + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'

        server._pool.query = ok_upstream  # type: ignore
        for i in range(3):
            await server.resolve(_make_query(xid=i, name=f'h{i}.example.com.'))
        self.assertEqual(server._stats['cache_misses'], 0)
        self.assertEqual(server._stats['cache_hits'], 0)
        await server.stop()


class TestStatsWriterLoop(unittest.IsolatedAsyncioTestCase):
    """The writer is the IPC bridge from dns_main to api_main; if its output
    shape changes, /v1/dns silently breaks."""

    def _make_config(self):
        cfg = MagicMock()
        cfg.dot_bind = '127.0.0.1'
        cfg.dot_port = 53
        cfg.dot_upstream = 'cloudflare'
        cfg.dot_upstreams = ['cloudflare']
        cfg.dot_caching = True
        cfg.dot_cache_ttl = 0
        cfg.dot_custom_server = ''
        cfg.dot_update_period = 0
        cfg.dot_pool_size = 1
        cfg.dot_query_timeout = 2.0
        cfg.dot_query_retries = 0
        cfg.dot_retry_backoff_ms = 0
        cfg.dot_block_ads = False
        cfg.dot_block_malware = False
        cfg.dot_block_tracking = False
        cfg.dot_enabled = True
        return cfg

    async def test_writer_emits_expected_shape(self):
        server = DOTServer(self._make_config(), 'vpn')
        # Seed cache so cache_size_bytes is non-zero
        server._cache[('a.example.com.', 1)] = (b'\x00' * 42, 9999.0)
        server._stats['queries_total'] = 7

        with tempfile.TemporaryDirectory() as td:
            state_dir = Path(td)
            task = asyncio.create_task(
                _stats_writer_loop(server, state_dir, interval=0.05)
            )
            try:
                stats_path = state_dir / 'dns_stats.json'
                for _ in range(40):
                    await asyncio.sleep(0.025)
                    if stats_path.exists():
                        break
                self.assertTrue(stats_path.exists(), "writer never produced file")
                data = json.loads(stats_path.read_text())
            finally:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        for key in ('upstreams', 'counters', 'cache_entries',
                    'cache_size_bytes', 'in_flight', 'blocked_domains'):
            self.assertIn(key, data, f"writer missing key: {key}")
        self.assertEqual(data['cache_entries'], 1)
        self.assertEqual(data['cache_size_bytes'], 42)
        self.assertEqual(data['counters']['queries_total'], 7)
        # Tmp file should not be left behind after a successful rename
        self.assertFalse((state_dir / 'dns_stats.json.tmp').exists())
        await server.stop()


if __name__ == '__main__':
    unittest.main()
