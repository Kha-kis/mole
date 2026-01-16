"""
Tests for mole_pkg.services.dns module - DNS over TLS service
"""

import asyncio
import struct
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

from mole_pkg.services.dns import (
    DOTServer,
    DOT_PROVIDERS,
)


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


if __name__ == '__main__':
    unittest.main()
