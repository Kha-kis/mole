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


class TestQBittorrentConnectionStatusRetry(unittest.IsolatedAsyncioTestCase):
    """get_connection_status retries on timeout and demotes single transient
    failures from ERROR to WARNING. The previous behavior generated spurious
    hourly ERRORs against high-torrent-count clients."""

    def _make_config(self, timeout=15):
        cfg = Mock()
        cfg.qb_api_url = "http://localhost:8080/api/v2/app"
        cfg.qb_api_timeout = timeout
        return cfg

    async def test_timeout_then_success_returns_value_at_warning(self):
        from mole_pkg.services import QBittorrentClient
        import socket

        client = QBittorrentClient(self._make_config())

        ok_resp = MagicMock()
        ok_resp.read.return_value = b'{"connection_status": "connected"}'
        ok_resp.__enter__ = lambda self_: self_
        ok_resp.__exit__ = lambda *a: False

        call_count = {"n": 0}
        def fake_urlopen(url, timeout=None):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise socket.timeout("timed out")
            return ok_resp

        with patch("mole_pkg.services.qbittorrent.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("mole_pkg.services.qbittorrent.log") as mock_log:
            result = await client.get_connection_status()

        self.assertEqual(result, "connected")
        self.assertEqual(call_count["n"], 2)
        mock_log.warning.assert_called_once()
        mock_log.error.assert_not_called()

    async def test_two_timeouts_returns_none_at_error(self):
        from mole_pkg.services import QBittorrentClient
        import socket

        client = QBittorrentClient(self._make_config())

        def fake_urlopen(url, timeout=None):
            raise socket.timeout("timed out")

        with patch("mole_pkg.services.qbittorrent.urllib.request.urlopen",
                   side_effect=fake_urlopen), \
             patch("mole_pkg.services.qbittorrent.log") as mock_log:
            result = await client.get_connection_status()

        self.assertIsNone(result)
        mock_log.warning.assert_called_once()
        mock_log.error.assert_called_once()


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


if __name__ == '__main__':
    unittest.main()
