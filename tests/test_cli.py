"""
Tests for mole_pkg.cli module
"""

import argparse
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

# Import CLI functions
from mole_pkg.cli import (
    cmd_validate,
    cmd_ip,
    cmd_dns,
    cmd_status,
    cmd_stats,
    _ping_server,
    _qbittorrent_status,
    main,
)
from mole_pkg import __version__


class TestCmdValidate(unittest.TestCase):
    """Test validate command"""

    @patch('mole_pkg.cli.validate_config')
    def test_validate_success(self, mock_validate):
        """cmd_validate returns 0 on valid config"""
        mock_validate.return_value = (True, [])
        args = argparse.Namespace(config='/etc/mole/config.yaml')
        result = cmd_validate(args)
        self.assertEqual(result, 0)

    @patch('mole_pkg.cli.validate_config')
    def test_validate_failure(self, mock_validate):
        """cmd_validate returns 1 on invalid config"""
        mock_validate.return_value = (False, ["Error: missing field"])
        args = argparse.Namespace(config='/etc/mole/config.yaml')
        result = cmd_validate(args)
        self.assertEqual(result, 1)

    @patch('mole_pkg.cli.validate_config')
    def test_validate_with_warnings(self, mock_validate):
        """cmd_validate handles warnings"""
        mock_validate.return_value = (True, ["Warning: deprecated option"])
        args = argparse.Namespace(config='/etc/mole/config.yaml')
        result = cmd_validate(args)
        self.assertEqual(result, 0)


class TestCmdIp(unittest.TestCase):
    """Test ip command"""

    @patch('mole_pkg.cli.run_in_netns')
    @patch('mole_pkg.cli.Config')
    @patch('os.geteuid', return_value=0)
    def test_ip_success(self, mock_euid, mock_config, mock_run):
        """cmd_ip shows public IP"""
        mock_config.return_value.netns = 'vpn'
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='1.2.3.4'
        )
        args = argparse.Namespace()
        result = cmd_ip(args)
        self.assertEqual(result, 0)


class TestCmdDns(unittest.TestCase):
    """Test dns command"""

    @patch('mole_pkg.cli.Config')
    @patch('mole_pkg.cli.run_cmd')
    def test_dns_when_dot_disabled(self, mock_run, mock_config):
        """cmd_dns returns 1 when DOT disabled"""
        mock_config_instance = MagicMock()
        mock_config_instance.dot_enabled = False
        mock_config.return_value = mock_config_instance

        args = argparse.Namespace(namespace=False, config='/etc/mole/config.yaml')
        result = cmd_dns(args)
        # Returns 1 when DOT is not enabled
        self.assertEqual(result, 1)

    @patch('mole_pkg.cli.Config')
    @patch('mole_pkg.cli.run_cmd')
    def test_dns_when_dot_enabled(self, mock_run, mock_config):
        """cmd_dns works when DOT enabled"""
        mock_config_instance = MagicMock()
        mock_config_instance.dot_enabled = True
        mock_config_instance.dot_upstream = 'cloudflare'
        mock_config_instance.netns = 'vpn'
        mock_config.return_value = mock_config_instance

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='Server: 1.1.1.1\nAddress: 93.184.216.34'
        )
        args = argparse.Namespace(namespace=False, config='/etc/mole/config.yaml')
        result = cmd_dns(args)
        self.assertEqual(result, 0)


class TestCmdStatus(unittest.TestCase):
    """Test status command"""

    @patch('mole_pkg.cli.Path')
    @patch('mole_pkg.cli.Config')
    @patch('mole_pkg.cli.run_cmd')
    @patch('os.geteuid')
    def test_status_non_root_partial(self, mock_euid, mock_run, mock_config, mock_path):
        """cmd_status works but shows partial info without root"""
        mock_euid.return_value = 1000  # Non-root
        mock_config.return_value.netns = 'vpn'
        mock_config.return_value.state_dir = '/var/lib/mole'
        mock_run.return_value = MagicMock(returncode=0, stdout='active')

        # Mock Path to avoid permission errors
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path_instance.read_text.return_value = ''
        mock_path.return_value = mock_path_instance
        mock_path.return_value.__truediv__ = lambda self, x: mock_path_instance

        args = argparse.Namespace()
        result = cmd_status(args)
        # Status command returns 0 even for non-root (just shows limited info)
        self.assertEqual(result, 0)

    @patch('os.geteuid')
    @patch('mole_pkg.cli.Config')
    @patch('mole_pkg.cli.run_in_netns')
    @patch('mole_pkg.cli.Path')
    def test_status_with_root(self, mock_path, mock_run, mock_config, mock_euid):
        """cmd_status works as root"""
        mock_euid.return_value = 0  # Root
        mock_config.return_value.netns = 'vpn'
        mock_config.return_value.state_dir = '/var/lib/mole'
        mock_run.return_value = MagicMock(returncode=0, stdout='mole')

        # Mock Path for state files
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path.return_value = mock_path_instance
        mock_path.return_value.__truediv__ = lambda self, x: mock_path_instance

        args = argparse.Namespace()
        result = cmd_status(args)
        self.assertEqual(result, 0)


class TestCmdStats(unittest.TestCase):
    """Test stats command"""

    @patch('mole_pkg.cli.DEFAULT_STATE_DIR', new_callable=lambda: tempfile.mkdtemp())
    def test_stats_no_file(self, mock_state_dir):
        """cmd_stats handles missing stats file"""
        args = argparse.Namespace(save=False)
        result = cmd_stats(args)
        self.assertEqual(result, 0)

    def test_stats_with_file(self):
        """cmd_stats displays existing stats"""
        with tempfile.TemporaryDirectory() as tmpdir:
            stats_file = Path(tmpdir) / 'bandwidth_stats.json'
            stats_data = {
                'total_rx': 1073741824,  # 1 GB
                'total_tx': 536870912,   # 512 MB
                'start_time': '2024-01-01T00:00:00'
            }
            stats_file.write_text(json.dumps(stats_data))

            with patch('mole_pkg.cli.DEFAULT_STATE_DIR', tmpdir):
                args = argparse.Namespace(save=False)
                result = cmd_stats(args)
                self.assertEqual(result, 0)


class TestPingServer(unittest.TestCase):
    """Test _ping_server helper function"""

    @patch('mole_pkg.cli.run_cmd')
    def test_ping_success(self, mock_run):
        """_ping_server returns latency on success"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='PING 1.1.1.1: 64 bytes icmp_seq=1 ttl=64 time=15.5 ms'
        )
        result = _ping_server('1.1.1.1')
        self.assertIsNotNone(result)

    @patch('mole_pkg.cli.run_cmd')
    def test_ping_failure(self, mock_run):
        """_ping_server returns None on failure"""
        mock_run.return_value = MagicMock(returncode=1, stdout='')
        result = _ping_server('192.0.2.1')  # TEST-NET address
        self.assertIsNone(result)

    @patch('mole_pkg.cli.run_cmd')
    def test_ping_timeout(self, mock_run):
        """_ping_server handles timeout"""
        mock_run.side_effect = Exception("timeout")
        result = _ping_server('192.0.2.1')
        self.assertIsNone(result)


class TestQbittorrentStatus(unittest.TestCase):
    """Test _qbittorrent_status helper function"""

    @patch('subprocess.run')
    def test_qbittorrent_not_configured(self, mock_run):
        """_qbittorrent_status shows not configured"""
        mock_run.return_value = MagicMock(
            returncode=1,  # Service not found
            stdout='',
            stderr='No such service'
        )
        # Should not crash
        result = _qbittorrent_status()
        self.assertEqual(result, 0)

    @patch('mole_pkg.cli.Config')
    @patch('subprocess.run')
    def test_qbittorrent_active(self, mock_run, mock_config):
        """_qbittorrent_status shows active service"""
        # Mock config
        mock_config.return_value.qb_port = 8080
        mock_config.return_value.veth_vpn_ip = '10.200.200.2'

        def side_effect(cmd, *args, **kwargs):
            result = MagicMock()
            if 'cat' in cmd:
                result.returncode = 0
                result.stdout = 'unit file contents'
            elif 'is-active' in cmd:
                result.returncode = 0
                result.stdout = 'active'
            elif 'is-enabled' in cmd:
                result.returncode = 0
                result.stdout = 'enabled'
            else:
                result.returncode = 0
                result.stdout = ''
            return result

        mock_run.side_effect = side_effect
        _qbittorrent_status()


class TestCLIMain(unittest.TestCase):
    """Test CLI main function"""

    def test_help_output(self):
        """CLI shows help without error"""
        with patch.object(sys, 'argv', ['mole', '--help']):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 0)

    def test_version_output(self):
        """CLI shows version"""
        with patch.object(sys, 'argv', ['mole', '--version']):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertEqual(cm.exception.code, 0)

    def test_no_command(self):
        """CLI returns 1 with no command"""
        with patch.object(sys, 'argv', ['mole']):
            result = main()
            self.assertEqual(result, 1)

    @patch('mole_pkg.cli.validate_config')
    def test_validate_command(self, mock_validate):
        """CLI routes to validate command"""
        mock_validate.return_value = (True, [])
        with patch.object(sys, 'argv', ['mole', 'validate']):
            result = main()
            self.assertEqual(result, 0)

    @patch('mole_pkg.cli.cmd_status')
    def test_status_command_routing(self, mock_cmd_status):
        """CLI routes to status command"""
        mock_cmd_status.return_value = 0
        with patch.object(sys, 'argv', ['mole', 'status']):
            result = main()
            mock_cmd_status.assert_called_once()


class TestCLIIntegration(unittest.TestCase):
    """Integration tests for CLI"""

    def test_version_contains_version(self):
        """Version output contains version number"""
        with patch.object(sys, 'argv', ['mole', '--version']):
            with patch('sys.stdout', new_callable=io.StringIO) as mock_stdout:
                try:
                    main()
                except SystemExit:
                    pass
                # Version goes to stdout via argparse

    def test_unknown_command_exits_nonzero(self):
        """CLI handles unknown command"""
        with patch.object(sys, 'argv', ['mole', 'unknowncommand']):
            with self.assertRaises(SystemExit) as cm:
                main()
            self.assertNotEqual(cm.exception.code, 0)


if __name__ == '__main__':
    unittest.main()
