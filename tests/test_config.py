"""
Tests for mole_pkg.config module
"""

import os
import tempfile
import unittest
from pathlib import Path

from mole_pkg.config import Config, load_config, validate_config


class TestLoadConfig(unittest.TestCase):
    """Test load_config function"""

    def test_load_nonexistent_file(self):
        """load_config returns empty dict for nonexistent file"""
        config = load_config("/nonexistent/path/config")
        self.assertEqual(config, {})

    def test_load_valid_config(self):
        """load_config parses key=value pairs"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("KEY1=value1\n")
            f.write("KEY2=value2\n")
            f.write("# comment\n")
            f.write("\n")
            f.write("KEY3=value with spaces\n")
            temp_path = f.name

        try:
            config = load_config(temp_path)
            self.assertEqual(config['KEY1'], 'value1')
            self.assertEqual(config['KEY2'], 'value2')
            self.assertEqual(config['KEY3'], 'value with spaces')
            self.assertNotIn('#', ''.join(config.keys()))
        finally:
            os.unlink(temp_path)

    def test_env_vars_override_config(self):
        """Environment variables override config file values"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("TEST_KEY=from_file\n")
            temp_path = f.name

        try:
            os.environ['TEST_KEY'] = 'from_env'
            config = load_config(temp_path)
            self.assertEqual(config['TEST_KEY'], 'from_env')
        finally:
            del os.environ['TEST_KEY']
            os.unlink(temp_path)


class TestConfig(unittest.TestCase):
    """Test Config class"""

    def setUp(self):
        """Create temp config file for tests"""
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
        self.temp_file.write("""
VPN_PROVIDER=pia
PIA_USER=testuser
PIA_PASS=testpass
PIA_REGION=us_east
NETNS_NAME=testvpn
VETH_HOST_IP=10.100.100.1
VETH_VPN_IP=10.100.100.2
HOST_INTERFACE=eth0
PORT_FORWARD=true
TORRENT_CLIENT=qbittorrent
QB_PORT=9000
QB_USER=testqb
RENEWAL_INTERVAL=3600
KEEPALIVE_INTERVAL=300
WATCHDOG_INTERVAL=30
WATCHDOG_MAX_FAILURES=5
DOT_ENABLED=true
DOT_UPSTREAM=quad9
DOT_BLOCK_ADS=true
DOT_BLOCK_MALWARE=false
DOT_CACHING=true
PROXY_ENABLED=false
HTTP_API_ENABLED=true
HTTP_API_PORT=9090
HTTP_API_BIND=0.0.0.0
HTTP_API_KEY=testapikey
""")
        self.temp_file.close()
        self.config = Config(self.temp_file.name)

    def tearDown(self):
        os.unlink(self.temp_file.name)

    def test_vpn_provider(self):
        self.assertEqual(self.config.vpn_provider, 'pia')

    def test_netns(self):
        self.assertEqual(self.config.netns, 'testvpn')

    def test_veth_host_ip(self):
        self.assertEqual(self.config.veth_host_ip, '10.100.100.1')

    def test_veth_vpn_ip(self):
        self.assertEqual(self.config.veth_vpn_ip, '10.100.100.2')

    def test_port_forward_true(self):
        self.assertTrue(self.config.port_forward)

    def test_qb_port(self):
        self.assertEqual(self.config.qb_port, 9000)

    def test_qb_user(self):
        self.assertEqual(self.config.qb_user, 'testqb')

    def test_renewal_interval(self):
        self.assertEqual(self.config.renewal_interval, 3600)

    def test_keepalive_interval(self):
        self.assertEqual(self.config.keepalive_interval, 300)

    def test_watchdog_interval(self):
        self.assertEqual(self.config.watchdog_interval, 30)

    def test_dot_enabled(self):
        self.assertTrue(self.config.dot_enabled)

    def test_dot_upstream(self):
        self.assertEqual(self.config.dot_upstream, 'quad9')

    def test_dot_block_ads(self):
        self.assertTrue(self.config.dot_block_ads)

    def test_dot_block_malware(self):
        self.assertFalse(self.config.dot_block_malware)

    def test_proxy_enabled(self):
        self.assertFalse(self.config.proxy_enabled)

    def test_http_api_enabled(self):
        self.assertTrue(self.config.http_api_enabled)

    def test_http_api_port(self):
        self.assertEqual(self.config.http_api_port, 9090)

    def test_http_api_key(self):
        self.assertEqual(self.config.http_api_key, 'testapikey')

    def test_get_method(self):
        self.assertEqual(self.config.get('PIA_USER'), 'testuser')

    def test_get_with_default(self):
        self.assertEqual(self.config.get('NONEXISTENT', 'default'), 'default')

    def test_get_int(self):
        self.assertEqual(self.config.get_int('QB_PORT', 0), 9000)

    def test_get_int_invalid(self):
        """get_int returns default for non-numeric values"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("INVALID_INT=notanumber\n")
            temp_path = f.name

        try:
            config = Config(temp_path)
            self.assertEqual(config.get_int('INVALID_INT', 42), 42)
        finally:
            os.unlink(temp_path)


class TestConfigDefaults(unittest.TestCase):
    """Test Config defaults when values are not set"""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
        self.temp_file.write("# Empty config\n")
        self.temp_file.close()
        self.config = Config(self.temp_file.name)

    def tearDown(self):
        os.unlink(self.temp_file.name)

    def test_default_vpn_provider(self):
        self.assertEqual(self.config.vpn_provider, 'pia')

    def test_default_netns(self):
        self.assertEqual(self.config.netns, 'vpn')

    def test_default_veth_host_ip(self):
        self.assertEqual(self.config.veth_host_ip, '10.200.200.1')

    def test_default_veth_vpn_ip(self):
        self.assertEqual(self.config.veth_vpn_ip, '10.200.200.2')

    def test_default_port_forward(self):
        self.assertTrue(self.config.port_forward)

    def test_default_dot_enabled(self):
        self.assertFalse(self.config.dot_enabled)

    def test_default_proxy_enabled(self):
        self.assertFalse(self.config.proxy_enabled)

    def test_default_http_api_enabled(self):
        self.assertFalse(self.config.http_api_enabled)


class TestValidateConfig(unittest.TestCase):
    """Test validate_config function"""

    def test_nonexistent_file(self):
        """validate_config returns error for nonexistent file"""
        is_valid, issues = validate_config("/nonexistent/config")
        self.assertFalse(is_valid)
        self.assertTrue(any("not found" in issue.lower() for issue in issues))

    def test_missing_credentials(self):
        """validate_config flags missing PIA credentials"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("VPN_PROVIDER=pia\n")
            f.write("PIA_USER=your_username\n")  # Default value
            f.write("PIA_PASS=your_password\n")  # Default value
            temp_path = f.name

        try:
            is_valid, issues = validate_config(temp_path)
            self.assertFalse(is_valid)
            self.assertTrue(any("PIA_USER" in issue for issue in issues))
            self.assertTrue(any("PIA_PASS" in issue for issue in issues))
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()
