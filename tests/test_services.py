"""
Tests for mole_pkg.services module
"""

import unittest
from unittest.mock import Mock, patch, MagicMock


class TestServicesImport(unittest.TestCase):
    """Test that services can be imported"""

    def test_import_qbittorrent(self):
        """QBittorrentClient can be imported"""
        from mole_pkg.services import QBittorrentClient, TorrentClient
        self.assertTrue(callable(QBittorrentClient))

    def test_import_dns(self):
        """DOTServer can be imported"""
        from mole_pkg.services import DOTServer
        self.assertTrue(callable(DOTServer))

    def test_import_proxy(self):
        """HTTPProxyServer can be imported"""
        from mole_pkg.services import HTTPProxyServer
        self.assertTrue(callable(HTTPProxyServer))

    def test_import_api(self):
        """HTTPAPIServer can be imported"""
        from mole_pkg.services import HTTPAPIServer
        self.assertTrue(callable(HTTPAPIServer))


class TestQBittorrentClient(unittest.TestCase):
    """Test QBittorrentClient"""

    def test_inherits_from_torrent_client(self):
        """QBittorrentClient inherits from TorrentClient"""
        from mole_pkg.services import QBittorrentClient, TorrentClient
        self.assertTrue(issubclass(QBittorrentClient, TorrentClient))

    def test_client_initialization(self):
        """QBittorrentClient initializes with config"""
        from mole_pkg.services import QBittorrentClient

        mock_config = Mock()
        mock_config.qb_api_url = "http://localhost:8080/api/v2/app"

        client = QBittorrentClient(mock_config)
        self.assertEqual(client.config, mock_config)


class TestDOTServer(unittest.TestCase):
    """Test DOTServer"""

    def test_server_initialization(self):
        """DOTServer initializes with config and netns"""
        from mole_pkg.services import DOTServer

        mock_config = Mock()
        mock_config.dot_bind = "10.200.200.2"
        mock_config.dot_port = 53
        mock_config.dot_upstream = "cloudflare"
        mock_config.dot_custom_server = ""
        mock_config.dot_caching = True
        mock_config.dot_cache_ttl = 0
        mock_config.state_dir = "/var/lib/mole"

        server = DOTServer(mock_config, "vpn")
        self.assertEqual(server.bind, "10.200.200.2")
        self.assertEqual(server.port, 53)
        self.assertEqual(server.netns, "vpn")

    def test_dot_providers_available(self):
        """DOT_PROVIDERS dictionary is available"""
        from mole_pkg.services.dns import DOT_PROVIDERS

        self.assertIn('cloudflare', DOT_PROVIDERS)
        self.assertIn('quad9', DOT_PROVIDERS)
        self.assertIn('google', DOT_PROVIDERS)


class TestHTTPProxyServer(unittest.TestCase):
    """Test HTTPProxyServer"""

    def test_server_initialization(self):
        """HTTPProxyServer initializes with config and netns"""
        from mole_pkg.services import HTTPProxyServer

        mock_config = Mock()
        mock_config.proxy_bind = "10.200.200.1"
        mock_config.proxy_port = 8888
        mock_config.proxy_user = "mole"
        mock_config.proxy_pass = "secret"

        server = HTTPProxyServer(mock_config, "vpn")
        self.assertEqual(server.bind, "10.200.200.1")
        self.assertEqual(server.port, 8888)
        self.assertEqual(server.user, "mole")
        self.assertEqual(server.password, "secret")

    def test_blocked_networks_defined(self):
        """BLOCKED_NETWORKS list is defined for SSRF protection"""
        from mole_pkg.services import HTTPProxyServer

        self.assertTrue(hasattr(HTTPProxyServer, 'BLOCKED_NETWORKS'))
        self.assertIsInstance(HTTPProxyServer.BLOCKED_NETWORKS, list)
        self.assertTrue(len(HTTPProxyServer.BLOCKED_NETWORKS) > 0)

    def test_is_blocked_target_localhost(self):
        """_is_blocked_target blocks localhost"""
        from mole_pkg.services import HTTPProxyServer

        mock_config = Mock()
        mock_config.proxy_bind = "0.0.0.0"
        mock_config.proxy_port = 8888
        mock_config.proxy_user = "user"
        mock_config.proxy_pass = "pass"
        mock_config.veth_host_ip = "10.200.200.1"
        mock_config.veth_vpn_ip = "10.200.200.2"

        server = HTTPProxyServer(mock_config, "vpn")
        self.assertTrue(server._is_blocked_target("localhost"))
        self.assertTrue(server._is_blocked_target("127.0.0.1"))

    def test_is_blocked_target_private_ip(self):
        """_is_blocked_target blocks private IPs"""
        from mole_pkg.services import HTTPProxyServer

        mock_config = Mock()
        mock_config.proxy_bind = "0.0.0.0"
        mock_config.proxy_port = 8888
        mock_config.proxy_user = "user"
        mock_config.proxy_pass = "pass"
        mock_config.veth_host_ip = "10.200.200.1"
        mock_config.veth_vpn_ip = "10.200.200.2"

        server = HTTPProxyServer(mock_config, "vpn")
        self.assertTrue(server._is_blocked_target("10.0.0.1"))
        self.assertTrue(server._is_blocked_target("192.168.1.1"))
        self.assertTrue(server._is_blocked_target("172.16.0.1"))

    def test_is_blocked_target_allows_public(self):
        """_is_blocked_target allows public IPs"""
        from mole_pkg.services import HTTPProxyServer

        mock_config = Mock()
        mock_config.proxy_bind = "0.0.0.0"
        mock_config.proxy_port = 8888
        mock_config.proxy_user = "user"
        mock_config.proxy_pass = "pass"
        mock_config.veth_host_ip = "10.200.200.1"
        mock_config.veth_vpn_ip = "10.200.200.2"

        server = HTTPProxyServer(mock_config, "vpn")
        self.assertFalse(server._is_blocked_target("8.8.8.8"))
        self.assertFalse(server._is_blocked_target("1.1.1.1"))


class TestHTTPAPIServer(unittest.TestCase):
    """Test HTTPAPIServer"""

    def test_server_initialization(self):
        """HTTPAPIServer initializes with mole, bind, port, and api_key"""
        from mole_pkg.services import HTTPAPIServer

        mock_mole = Mock()
        server = HTTPAPIServer(mock_mole, "127.0.0.1", 8080, "testapikey")

        self.assertEqual(server.mole, mock_mole)
        self.assertEqual(server.bind, "127.0.0.1")
        self.assertEqual(server.port, 8080)
        self.assertEqual(server.api_key, "testapikey")

    def test_check_auth_no_key_configured(self):
        """_check_auth allows all when no API key is configured"""
        from mole_pkg.services import HTTPAPIServer

        mock_mole = Mock()
        server = HTTPAPIServer(mock_mole, "127.0.0.1", 8080, "")

        self.assertTrue(server._check_auth({}, {}))

    def test_check_auth_header_key(self):
        """_check_auth validates X-API-Key header"""
        from mole_pkg.services import HTTPAPIServer

        mock_mole = Mock()
        server = HTTPAPIServer(mock_mole, "127.0.0.1", 8080, "secretkey")

        headers = {"x-api-key": "secretkey"}
        self.assertTrue(server._check_auth(headers, {}))

        headers = {"x-api-key": "wrongkey"}
        self.assertFalse(server._check_auth(headers, {}))

    def test_check_auth_bearer_token(self):
        """_check_auth validates Authorization: Bearer header"""
        from mole_pkg.services import HTTPAPIServer

        mock_mole = Mock()
        server = HTTPAPIServer(mock_mole, "127.0.0.1", 8080, "secretkey")

        headers = {"authorization": "Bearer secretkey"}
        self.assertTrue(server._check_auth(headers, {}))

        headers = {"authorization": "Bearer wrongkey"}
        self.assertFalse(server._check_auth(headers, {}))

    def test_check_auth_query_param(self):
        """_check_auth validates api_key query parameter"""
        from mole_pkg.services import HTTPAPIServer

        mock_mole = Mock()
        server = HTTPAPIServer(mock_mole, "127.0.0.1", 8080, "secretkey")

        query_params = {"api_key": "secretkey"}
        self.assertTrue(server._check_auth({}, query_params))

        query_params = {"api_key": "wrongkey"}
        self.assertFalse(server._check_auth({}, query_params))


if __name__ == '__main__':
    unittest.main()
