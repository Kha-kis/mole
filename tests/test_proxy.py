"""
Tests for mole_pkg.services.proxy module - HTTP Proxy service
"""

import asyncio
import base64
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

from mole_pkg.services.proxy import HTTPProxyServer
from mole_pkg.services.proxy_main import (
    HTTPProxyServerStandalone,
    BLOCKED_NETWORKS,
    main,
)


class TestBlockedNetworks(unittest.TestCase):
    """Test BLOCKED_NETWORKS configuration"""

    def test_blocked_networks_exist(self):
        """BLOCKED_NETWORKS list is defined"""
        self.assertIsInstance(BLOCKED_NETWORKS, list)
        self.assertGreater(len(BLOCKED_NETWORKS), 0)

    def test_loopback_blocked(self):
        """Loopback addresses are in blocked list"""
        all_prefixes = [prefix for group in BLOCKED_NETWORKS for prefix in group]
        self.assertIn('127.', all_prefixes)

    def test_private_class_a_blocked(self):
        """Private Class A (10.x) is blocked"""
        all_prefixes = [prefix for group in BLOCKED_NETWORKS for prefix in group]
        self.assertIn('10.', all_prefixes)

    def test_private_class_c_blocked(self):
        """Private Class C (192.168.x) is blocked"""
        all_prefixes = [prefix for group in BLOCKED_NETWORKS for prefix in group]
        self.assertIn('192.168.', all_prefixes)

    def test_private_class_b_blocked(self):
        """Private Class B (172.16-31.x) is blocked"""
        all_prefixes = [prefix for group in BLOCKED_NETWORKS for prefix in group]
        self.assertIn('172.16.', all_prefixes)
        self.assertIn('172.31.', all_prefixes)

    def test_link_local_blocked(self):
        """Link-local (169.254.x) is blocked"""
        all_prefixes = [prefix for group in BLOCKED_NETWORKS for prefix in group]
        self.assertIn('169.254.', all_prefixes)


class TestHTTPProxyServerStandaloneInit(unittest.TestCase):
    """Test HTTPProxyServerStandalone initialization"""

    def test_init_with_defaults(self):
        """Server initializes with default veth IPs"""
        server = HTTPProxyServerStandalone(
            bind='127.0.0.1',
            port=8888,
            user='testuser',
            password='testpass'
        )

        self.assertEqual(server.bind, '127.0.0.1')
        self.assertEqual(server.port, 8888)
        self.assertEqual(server.user, 'testuser')
        self.assertEqual(server.password, 'testpass')
        self.assertEqual(server.veth_host_ip, '10.200.200.1')
        self.assertEqual(server.veth_vpn_ip, '10.200.200.2')
        self.assertIsNone(server._server)

    def test_init_with_custom_veth(self):
        """Server accepts custom veth IPs"""
        server = HTTPProxyServerStandalone(
            bind='0.0.0.0',
            port=3128,
            user='admin',
            password='secret',
            veth_host_ip='192.168.100.1',
            veth_vpn_ip='192.168.100.2'
        )

        self.assertEqual(server.veth_host_ip, '192.168.100.1')
        self.assertEqual(server.veth_vpn_ip, '192.168.100.2')


class TestHTTPProxyServerIsBlockedTarget(unittest.TestCase):
    """Test HTTPProxyServerStandalone._is_blocked_target"""

    def setUp(self):
        self.server = HTTPProxyServerStandalone(
            bind='127.0.0.1',
            port=8888,
            user='test',
            password='test',
            veth_host_ip='10.200.200.1',
            veth_vpn_ip='10.200.200.2'
        )

    def test_blocks_localhost(self):
        """Blocks localhost hostname"""
        self.assertTrue(self.server._is_blocked_target('localhost'))
        self.assertTrue(self.server._is_blocked_target('LOCALHOST'))
        self.assertTrue(self.server._is_blocked_target('localhost.localdomain'))

    def test_blocks_metadata_hostnames(self):
        """Blocks cloud metadata hostnames"""
        self.assertTrue(self.server._is_blocked_target('metadata.google.internal'))
        self.assertTrue(self.server._is_blocked_target('metadata'))
        self.assertTrue(self.server._is_blocked_target('169.254.169.254'))

    def test_blocks_veth_addresses(self):
        """Blocks configured veth addresses"""
        self.assertTrue(self.server._is_blocked_target('10.200.200.1'))
        self.assertTrue(self.server._is_blocked_target('10.200.200.2'))

    def test_blocks_loopback_ips(self):
        """Blocks loopback IP addresses"""
        self.assertTrue(self.server._is_blocked_target('127.0.0.1'))
        self.assertTrue(self.server._is_blocked_target('127.1.2.3'))

    def test_blocks_private_class_a(self):
        """Blocks private Class A addresses"""
        self.assertTrue(self.server._is_blocked_target('10.0.0.1'))
        self.assertTrue(self.server._is_blocked_target('10.255.255.255'))

    def test_blocks_private_class_b(self):
        """Blocks private Class B addresses"""
        self.assertTrue(self.server._is_blocked_target('172.16.0.1'))
        self.assertTrue(self.server._is_blocked_target('172.31.255.255'))

    def test_blocks_private_class_c(self):
        """Blocks private Class C addresses"""
        self.assertTrue(self.server._is_blocked_target('192.168.0.1'))
        self.assertTrue(self.server._is_blocked_target('192.168.255.255'))

    def test_blocks_link_local(self):
        """Blocks link-local addresses"""
        self.assertTrue(self.server._is_blocked_target('169.254.0.1'))
        self.assertTrue(self.server._is_blocked_target('169.254.255.255'))

    def test_allows_public_ips(self):
        """Allows public IP addresses"""
        self.assertFalse(self.server._is_blocked_target('8.8.8.8'))
        self.assertFalse(self.server._is_blocked_target('1.1.1.1'))
        self.assertFalse(self.server._is_blocked_target('93.184.216.34'))

    def test_allows_public_hostnames(self):
        """Allows public hostnames"""
        self.assertFalse(self.server._is_blocked_target('example.com'))
        self.assertFalse(self.server._is_blocked_target('google.com'))
        self.assertFalse(self.server._is_blocked_target('www.example.org'))

    def test_handles_edge_cases(self):
        """Handles edge case addresses"""
        # Invalid/broadcast ranges
        self.assertTrue(self.server._is_blocked_target('0.0.0.0'))
        self.assertTrue(self.server._is_blocked_target('255.255.255.255'))


class TestHTTPProxyServerCheckAuth(unittest.TestCase):
    """Test HTTPProxyServerStandalone._check_auth"""

    def setUp(self):
        self.server = HTTPProxyServerStandalone(
            bind='127.0.0.1',
            port=8888,
            user='testuser',
            password='testpass'
        )

    def test_valid_auth(self):
        """Accepts valid credentials"""
        credentials = base64.b64encode(b'testuser:testpass').decode('utf-8')
        headers = {'proxy-authorization': f'Basic {credentials}'}
        self.assertTrue(self.server._check_auth(headers))

    def test_invalid_password(self):
        """Rejects invalid password"""
        credentials = base64.b64encode(b'testuser:wrongpass').decode('utf-8')
        headers = {'proxy-authorization': f'Basic {credentials}'}
        self.assertFalse(self.server._check_auth(headers))

    def test_invalid_username(self):
        """Rejects invalid username"""
        credentials = base64.b64encode(b'wronguser:testpass').decode('utf-8')
        headers = {'proxy-authorization': f'Basic {credentials}'}
        self.assertFalse(self.server._check_auth(headers))

    def test_missing_auth_header(self):
        """Rejects missing auth header"""
        headers = {}
        self.assertFalse(self.server._check_auth(headers))

    def test_non_basic_auth(self):
        """Rejects non-Basic auth schemes"""
        headers = {'proxy-authorization': 'Bearer sometoken'}
        self.assertFalse(self.server._check_auth(headers))

    def test_invalid_base64(self):
        """Handles invalid base64 encoding"""
        headers = {'proxy-authorization': 'Basic not-valid-base64!!!'}
        self.assertFalse(self.server._check_auth(headers))

    def test_malformed_credentials(self):
        """Handles malformed credentials (no colon)"""
        credentials = base64.b64encode(b'nocolon').decode('utf-8')
        headers = {'proxy-authorization': f'Basic {credentials}'}
        self.assertFalse(self.server._check_auth(headers))

    def test_empty_auth_header(self):
        """Handles empty auth header"""
        headers = {'proxy-authorization': ''}
        self.assertFalse(self.server._check_auth(headers))

    def test_basic_prefix_only(self):
        """Handles 'Basic ' prefix only"""
        headers = {'proxy-authorization': 'Basic '}
        self.assertFalse(self.server._check_auth(headers))


class TestHTTPProxyServerAsync(unittest.TestCase):
    """Test HTTPProxyServerStandalone async operations"""

    def test_server_not_started(self):
        """Server is not started initially"""
        server = HTTPProxyServerStandalone(
            bind='127.0.0.1',
            port=8888,
            user='test',
            password='test'
        )
        self.assertIsNone(server._server)

    def test_stop_when_not_started(self):
        """stop() handles case when server not started"""
        server = HTTPProxyServerStandalone(
            bind='127.0.0.1',
            port=8888,
            user='test',
            password='test'
        )

        # Should not raise
        asyncio.run(server.stop())


class TestHTTPProxyServerSendMethods(unittest.TestCase):
    """Test HTTPProxyServerStandalone send methods"""

    def test_send_auth_required(self):
        """_send_auth_required sends 407 response"""
        server = HTTPProxyServerStandalone(
            bind='127.0.0.1',
            port=8888,
            user='test',
            password='test'
        )

        async def run_test():
            mock_writer = MagicMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()

            await server._send_auth_required(mock_writer)

            # Verify response was written
            mock_writer.write.assert_called_once()
            call_args = mock_writer.write.call_args[0][0]
            self.assertIn(b'407', call_args)
            self.assertIn(b'Proxy Authentication Required', call_args)
            mock_writer.drain.assert_called_once()

        asyncio.run(run_test())

    def test_send_error(self):
        """_send_error sends correct HTTP error"""
        server = HTTPProxyServerStandalone(
            bind='127.0.0.1',
            port=8888,
            user='test',
            password='test'
        )

        async def run_test():
            mock_writer = MagicMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()

            await server._send_error(mock_writer, 403, "Forbidden")

            call_args = mock_writer.write.call_args[0][0]
            self.assertIn(b'403', call_args)
            self.assertIn(b'Forbidden', call_args)

        asyncio.run(run_test())


class TestHTTPProxyServerMainClass(unittest.TestCase):
    """Test HTTPProxyServer (namespace version) class"""

    def test_init(self):
        """HTTPProxyServer initializes correctly"""
        mock_config = MagicMock()
        mock_config.proxy_bind = '127.0.0.1'
        mock_config.proxy_port = 8888
        mock_config.proxy_user = 'testuser'
        mock_config.proxy_pass = 'testpass'
        mock_config.veth_host_ip = '10.200.200.1'
        mock_config.veth_vpn_ip = '10.200.200.2'

        server = HTTPProxyServer(mock_config, 'vpn')

        self.assertEqual(server.bind, '127.0.0.1')
        self.assertEqual(server.port, 8888)
        self.assertEqual(server.user, 'testuser')
        self.assertEqual(server.password, 'testpass')
        self.assertEqual(server.netns, 'vpn')

    def test_is_blocked_target_localhost(self):
        """HTTPProxyServer blocks localhost"""
        mock_config = MagicMock()
        mock_config.proxy_bind = '127.0.0.1'
        mock_config.proxy_port = 8888
        mock_config.proxy_user = 'test'
        mock_config.proxy_pass = 'test'
        mock_config.veth_host_ip = '10.200.200.1'
        mock_config.veth_vpn_ip = '10.200.200.2'

        server = HTTPProxyServer(mock_config, 'vpn')

        self.assertTrue(server._is_blocked_target('localhost'))
        self.assertTrue(server._is_blocked_target('127.0.0.1'))

    def test_is_blocked_target_veth(self):
        """HTTPProxyServer blocks veth IPs"""
        mock_config = MagicMock()
        mock_config.proxy_bind = '127.0.0.1'
        mock_config.proxy_port = 8888
        mock_config.proxy_user = 'test'
        mock_config.proxy_pass = 'test'
        mock_config.veth_host_ip = '10.200.200.1'
        mock_config.veth_vpn_ip = '10.200.200.2'

        server = HTTPProxyServer(mock_config, 'vpn')

        self.assertTrue(server._is_blocked_target('10.200.200.1'))
        self.assertTrue(server._is_blocked_target('10.200.200.2'))


class TestProxyMainArgParser(unittest.TestCase):
    """Test proxy_main argument parsing"""

    @patch('mole_pkg.services.proxy_main.asyncio.run')
    @patch('mole_pkg.services.proxy_main.log')
    def test_main_with_env_password(self, mock_log, mock_run):
        """main() accepts password from environment"""
        import sys
        import os

        original_argv = sys.argv
        original_env = os.environ.get('MOLE_PROXY_PASS')

        try:
            os.environ['MOLE_PROXY_PASS'] = 'envpassword'
            sys.argv = ['proxy_main', '--user', 'testuser']

            result = main()

            # Password from env should work
            self.assertEqual(result, 0)
        finally:
            sys.argv = original_argv
            if original_env is not None:
                os.environ['MOLE_PROXY_PASS'] = original_env
            elif 'MOLE_PROXY_PASS' in os.environ:
                del os.environ['MOLE_PROXY_PASS']

    @patch('mole_pkg.services.proxy_main.log')
    def test_main_missing_password(self, mock_log):
        """main() fails without password"""
        import sys
        import os

        original_argv = sys.argv
        original_env = os.environ.get('MOLE_PROXY_PASS')

        try:
            if 'MOLE_PROXY_PASS' in os.environ:
                del os.environ['MOLE_PROXY_PASS']
            sys.argv = ['proxy_main', '--user', 'testuser']

            result = main()

            # Should fail without password
            self.assertEqual(result, 1)
        finally:
            sys.argv = original_argv
            if original_env is not None:
                os.environ['MOLE_PROXY_PASS'] = original_env

    @patch('mole_pkg.services.proxy_main.asyncio.run')
    @patch('mole_pkg.services.proxy_main.log')
    def test_main_with_cli_password(self, mock_log, mock_run):
        """main() accepts password from CLI"""
        import sys
        import os

        original_argv = sys.argv
        original_env = os.environ.get('MOLE_PROXY_PASS')

        try:
            if 'MOLE_PROXY_PASS' in os.environ:
                del os.environ['MOLE_PROXY_PASS']
            sys.argv = ['proxy_main', '--user', 'testuser', '--password', 'clipass']

            result = main()

            self.assertEqual(result, 0)
        finally:
            sys.argv = original_argv
            if original_env is not None:
                os.environ['MOLE_PROXY_PASS'] = original_env


class TestHTTPProxyServerPipe(unittest.TestCase):
    """Test HTTPProxyServerStandalone._pipe method"""

    def test_pipe_data_transfer(self):
        """_pipe transfers data between reader and writer"""
        server = HTTPProxyServerStandalone(
            bind='127.0.0.1',
            port=8888,
            user='test',
            password='test'
        )

        async def run_test():
            mock_reader = AsyncMock()
            mock_reader.read = AsyncMock(side_effect=[b'test data', b''])

            mock_writer = MagicMock()
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = MagicMock()

            await server._pipe(mock_reader, mock_writer)

            mock_writer.write.assert_called_with(b'test data')

        asyncio.run(run_test())


if __name__ == '__main__':
    unittest.main()
