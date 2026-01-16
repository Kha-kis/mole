"""
Tests for mole_pkg.mole module - Main orchestrator
"""

import asyncio
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

from mole_pkg.mole import (
    Mole,
    get_vpn_provider,
    get_torrent_client,
)
from mole_pkg.config import Config
from mole_pkg.utils import VPNState


class TestGetVpnProvider(unittest.TestCase):
    """Test get_vpn_provider factory function"""

    @patch('mole_pkg.mole.Config')
    def test_get_pia_provider(self, mock_config):
        """get_vpn_provider returns PIAProvider for 'pia'"""
        mock_config_instance = MagicMock()
        mock_config_instance.vpn_provider = 'pia'
        state = VPNState()

        provider = get_vpn_provider(mock_config_instance, state)
        self.assertEqual(provider.name, 'PIA')

    @patch('mole_pkg.mole.Config')
    def test_get_proton_provider(self, mock_config):
        """get_vpn_provider returns ProtonProvider for 'proton'"""
        mock_config_instance = MagicMock()
        mock_config_instance.vpn_provider = 'proton'
        mock_config_instance.state_dir = '/var/lib/mole'
        state = VPNState()

        provider = get_vpn_provider(mock_config_instance, state)
        self.assertEqual(provider.name, 'ProtonVPN')

    @patch('mole_pkg.mole.Config')
    def test_get_protonvpn_alias(self, mock_config):
        """get_vpn_provider accepts 'protonvpn' alias"""
        mock_config_instance = MagicMock()
        mock_config_instance.vpn_provider = 'protonvpn'
        mock_config_instance.state_dir = '/var/lib/mole'
        state = VPNState()

        provider = get_vpn_provider(mock_config_instance, state)
        self.assertEqual(provider.name, 'ProtonVPN')

    @patch('mole_pkg.mole.Config')
    def test_unknown_provider_raises(self, mock_config):
        """get_vpn_provider raises for unknown provider"""
        mock_config_instance = MagicMock()
        mock_config_instance.vpn_provider = 'unknown'
        state = VPNState()

        with self.assertRaises(ValueError) as cm:
            get_vpn_provider(mock_config_instance, state)
        self.assertIn('unknown', str(cm.exception).lower())


class TestGetTorrentClient(unittest.TestCase):
    """Test get_torrent_client factory function"""

    def test_get_qbittorrent_client(self):
        """get_torrent_client returns QBittorrentClient"""
        mock_config = MagicMock()
        mock_config.torrent_client = 'qbittorrent'

        client = get_torrent_client(mock_config)
        self.assertIsNotNone(client)

    def test_get_none_client(self):
        """get_torrent_client returns None for 'none'"""
        mock_config = MagicMock()
        mock_config.torrent_client = 'none'

        client = get_torrent_client(mock_config)
        self.assertIsNone(client)

    def test_get_disabled_client(self):
        """get_torrent_client returns None for 'disabled'"""
        mock_config = MagicMock()
        mock_config.torrent_client = 'disabled'

        client = get_torrent_client(mock_config)
        self.assertIsNone(client)

    def test_get_empty_client(self):
        """get_torrent_client returns None for empty string"""
        mock_config = MagicMock()
        mock_config.torrent_client = ''

        client = get_torrent_client(mock_config)
        self.assertIsNone(client)

    def test_unknown_client_raises(self):
        """get_torrent_client raises for unknown client"""
        mock_config = MagicMock()
        mock_config.torrent_client = 'unknown_client'

        with self.assertRaises(ValueError):
            get_torrent_client(mock_config)


class TestMoleInit(unittest.TestCase):
    """Test Mole class initialization"""

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    def test_mole_init(self, mock_torrent, mock_provider, mock_config):
        """Mole initializes correctly"""
        mock_config_instance = MagicMock()
        mock_config_instance.vpn_provider = 'pia'
        mock_config_instance.torrent_client = 'none'
        mock_config.return_value = mock_config_instance

        mock_provider_instance = MagicMock()
        mock_provider_instance.name = 'PIA'
        mock_provider.return_value = mock_provider_instance

        mock_torrent.return_value = None

        mole = Mole()

        self.assertIsNotNone(mole.config)
        self.assertIsNotNone(mole.state)
        self.assertIsNotNone(mole.provider)
        self.assertFalse(mole.shutdown_event.is_set())

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    def test_mole_init_with_path(self, mock_torrent, mock_provider, mock_config):
        """Mole accepts custom config path"""
        mock_config_instance = MagicMock()
        mock_config.return_value = mock_config_instance
        mock_provider.return_value = MagicMock()
        mock_torrent.return_value = None

        mole = Mole(config_path='/custom/config')

        mock_config.assert_called_with('/custom/config')


class TestMoleSubprocessEnv(unittest.TestCase):
    """Test Mole subprocess environment handling"""

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    def test_get_subprocess_env(self, mock_torrent, mock_provider, mock_config):
        """_get_subprocess_env includes PYTHONPATH"""
        mock_config.return_value = MagicMock()
        mock_provider.return_value = MagicMock()
        mock_torrent.return_value = None

        mole = Mole()
        env = mole._get_subprocess_env()

        self.assertIn('PYTHONPATH', env)
        self.assertEqual(env['PYTHONPATH'], '/usr/local/lib/mole')


class TestMoleSignalHandler(unittest.TestCase):
    """Test Mole signal handling"""

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    def test_signal_handler_sets_shutdown(self, mock_torrent, mock_provider, mock_config):
        """_signal_handler sets shutdown event"""
        mock_config.return_value = MagicMock()
        mock_provider.return_value = MagicMock()
        mock_torrent.return_value = None

        mole = Mole()
        self.assertFalse(mole.shutdown_event.is_set())

        mole._signal_handler()

        self.assertTrue(mole.shutdown_event.is_set())


class TestMoleStopSubprocess(unittest.TestCase):
    """Test Mole subprocess management"""

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    def test_stop_subprocess_none(self, mock_torrent, mock_provider, mock_config):
        """_stop_subprocess handles None gracefully"""
        mock_config.return_value = MagicMock()
        mock_provider.return_value = MagicMock()
        mock_torrent.return_value = None

        mole = Mole()
        # Should not raise
        mole._stop_subprocess(None, "test")

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    def test_stop_subprocess_already_stopped(self, mock_torrent, mock_provider, mock_config):
        """_stop_subprocess handles already stopped process"""
        mock_config.return_value = MagicMock()
        mock_provider.return_value = MagicMock()
        mock_torrent.return_value = None

        mole = Mole()

        # Create a mock process that's already stopped
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0  # Already terminated

        mole._stop_subprocess(mock_proc, "test")
        mock_proc.terminate.assert_not_called()

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    def test_stop_subprocess_running(self, mock_torrent, mock_provider, mock_config):
        """_stop_subprocess terminates running process"""
        mock_config.return_value = MagicMock()
        mock_provider.return_value = MagicMock()
        mock_torrent.return_value = None

        mole = Mole()

        # Create a mock process that's running
        mock_proc = MagicMock()
        mock_proc.poll.return_value = None  # Still running
        mock_proc.pid = 12345

        mole._stop_subprocess(mock_proc, "test")
        mock_proc.terminate.assert_called_once()


class TestMoleWriteStateFiles(unittest.TestCase):
    """Test Mole state file writing"""

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    @patch('mole_pkg.mole.secure_write_file')
    def test_write_state_files(self, mock_write, mock_torrent, mock_provider, mock_config):
        """_write_state_files writes all state"""
        mock_config_instance = MagicMock()
        mock_config_instance.state_dir = '/var/lib/mole'
        mock_config.return_value = mock_config_instance
        mock_provider.return_value = MagicMock()
        mock_torrent.return_value = None

        mole = Mole()
        mole.state.server_ip = '1.2.3.4'
        mole.state.server_hostname = 'test.server.com'
        mole.state.server_vip = '10.0.0.1'
        mole.state.peer_ip = '10.0.0.2'
        mole.state.port = 12345

        mole._write_state_files()

        # Verify secure_write_file was called for each state
        self.assertEqual(mock_write.call_count, 5)


class TestMoleCheckHealth(unittest.TestCase):
    """Test Mole health check"""

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    @patch('mole_pkg.mole.run_in_netns')
    def test_check_health_interface_missing(self, mock_run, mock_torrent, mock_provider, mock_config):
        """_check_health returns False when interface missing"""
        mock_config_instance = MagicMock()
        mock_config_instance.netns = 'vpn'
        mock_config.return_value = mock_config_instance
        mock_provider.return_value = MagicMock()
        mock_torrent.return_value = None

        mock_run.return_value = MagicMock(returncode=1)  # Interface not found

        mole = Mole()
        result = asyncio.run(mole._check_health())
        self.assertFalse(result)

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    @patch('mole_pkg.mole.run_in_netns')
    def test_check_health_success(self, mock_run, mock_torrent, mock_provider, mock_config):
        """_check_health returns True when healthy"""
        mock_config_instance = MagicMock()
        mock_config_instance.netns = 'vpn'
        mock_config.return_value = mock_config_instance
        mock_provider.return_value = MagicMock()
        mock_torrent.return_value = None

        # Mock successful responses
        def run_side_effect(cmd, netns, check=True):
            result = MagicMock()
            if 'link' in cmd:
                result.returncode = 0
            elif 'wg' in cmd and 'latest-handshakes' in cmd:
                result.returncode = 0
                # Recent handshake (current timestamp)
                result.stdout = f'peer\t{int(datetime.now().timestamp())}'
            elif 'ping' in cmd:
                result.returncode = 0
            else:
                result.returncode = 0
            return result

        mock_run.side_effect = run_side_effect

        mole = Mole()
        mole.state.server_vip = '10.0.0.1'

        result = asyncio.run(mole._check_health())
        self.assertTrue(result)


class TestMoleAsync(unittest.TestCase):
    """Test Mole async operations"""

    @patch('mole_pkg.mole.Config')
    @patch('mole_pkg.mole.get_vpn_provider')
    @patch('mole_pkg.mole.get_torrent_client')
    def test_cleanup(self, mock_torrent, mock_provider, mock_config):
        """_cleanup cancels tasks and disconnects"""
        mock_config_instance = MagicMock()
        mock_config.return_value = mock_config_instance
        mock_provider.return_value = MagicMock()
        mock_torrent.return_value = None

        mole = Mole()

        # Create mock tasks
        mock_task = MagicMock()
        mole._keepalive_task = mock_task
        mole._watchdog_task = mock_task
        mole._restart_watcher_task = mock_task

        with patch('mole_pkg.mole.disconnect_vpn') as mock_disconnect:
            asyncio.run(mole._cleanup())

            # Verify tasks were cancelled
            self.assertEqual(mock_task.cancel.call_count, 3)
            mock_disconnect.assert_called_once()


if __name__ == '__main__':
    unittest.main()
