"""
Tests for mole_pkg.network module

Note: Most network functions require root privileges and actual network namespaces,
so we only test the functions that can be safely tested without privileges.
"""

import unittest
from unittest.mock import Mock, patch


class TestNetworkModuleImport(unittest.TestCase):
    """Test that network module can be imported"""

    def test_import_module(self):
        """Network module imports without errors"""
        from mole_pkg import network
        self.assertTrue(hasattr(network, 'setup_namespace'))
        self.assertTrue(hasattr(network, 'setup_killswitch'))
        self.assertTrue(hasattr(network, 'cleanup_namespace'))
        self.assertTrue(hasattr(network, 'connect_vpn'))
        self.assertTrue(hasattr(network, 'disconnect_vpn'))


class TestNetworkFunctions(unittest.TestCase):
    """Test network functions with mocked subprocess calls"""

    @patch('mole_pkg.network.run_cmd')
    @patch('mole_pkg.network.run_in_netns')
    def test_cleanup_namespace_calls_correct_commands(self, mock_run_in_netns, mock_run_cmd):
        """cleanup_namespace calls ip commands to delete namespace"""
        from mole_pkg.network import cleanup_namespace

        mock_run_cmd.return_value = Mock(returncode=0)
        cleanup_namespace("testvpn")

        # Should try to delete veth-host
        mock_run_cmd.assert_any_call(
            ["ip", "link", "del", "veth-host"],
            check=False
        )
        # Should try to delete namespace
        mock_run_cmd.assert_any_call(
            ["ip", "netns", "del", "testvpn"],
            check=False
        )


if __name__ == '__main__':
    unittest.main()
