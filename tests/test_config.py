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


# ---------- KEEPALIVE_INTERVAL provider-aware default ----------

class TestKeepaliveIntervalProviderAware(unittest.TestCase):
    """Default depends on VPN_PROVIDER. Explicit value always wins."""

    def _config_with(self, **overrides) -> Config:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("PIA_USER=u\n")
            f.write("PIA_PASS=p\n")
            for key, val in overrides.items():
                f.write(f"{key}={val}\n")
            self._tmp_path = f.name
        return Config(self._tmp_path)

    def tearDown(self):
        try:
            os.unlink(self._tmp_path)
        except (AttributeError, FileNotFoundError):
            pass

    def test_proton_default_is_45(self):
        c = self._config_with(VPN_PROVIDER='proton')
        self.assertEqual(c.keepalive_interval, 45)

    def test_pia_default_is_900(self):
        c = self._config_with(VPN_PROVIDER='pia')
        self.assertEqual(c.keepalive_interval, 900)

    def test_unknown_provider_falls_back_to_pia_default(self):
        c = self._config_with(VPN_PROVIDER='mystery')
        self.assertEqual(c.keepalive_interval, 900)

    def test_explicit_value_wins_for_proton(self):
        c = self._config_with(VPN_PROVIDER='proton', KEEPALIVE_INTERVAL='60')
        self.assertEqual(c.keepalive_interval, 60)

    def test_explicit_value_wins_for_pia(self):
        c = self._config_with(VPN_PROVIDER='pia', KEEPALIVE_INTERVAL='45')
        self.assertEqual(c.keepalive_interval, 45)

    def test_garbage_explicit_falls_back_to_provider_default(self):
        c = self._config_with(VPN_PROVIDER='proton', KEEPALIVE_INTERVAL='not-a-number')
        self.assertEqual(c.keepalive_interval, 45)

    def test_empty_explicit_value_falls_back_to_provider_default(self):
        # Operator setting `KEEPALIVE_INTERVAL=` (empty) should still get
        # the provider-aware default rather than parsing 0 or raising.
        c = self._config_with(VPN_PROVIDER='proton', KEEPALIVE_INTERVAL='')
        self.assertEqual(c.keepalive_interval, 45)

    def test_provider_case_insensitive(self):
        c = self._config_with(VPN_PROVIDER='PROTON')
        self.assertEqual(c.keepalive_interval, 45)


# ---------- HTTP_API_REQUIRE_AUTH tri-state ----------

class TestHttpApiRequireAuth(unittest.TestCase):
    """Test the tri-state HTTP_API_REQUIRE_AUTH parsing + helper logic."""

    def _config_with(self, **overrides) -> Config:
        """Build a Config from a tempfile with the given KEY=VALUE pairs."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("VPN_PROVIDER=pia\n")
            f.write("PIA_USER=u\n")
            f.write("PIA_PASS=p\n")
            for key, val in overrides.items():
                f.write(f"{key}={val}\n")
            self._tmp_path = f.name
        return Config(self._tmp_path)

    def tearDown(self):
        try:
            os.unlink(self._tmp_path)
        except (AttributeError, FileNotFoundError):
            pass

    def test_default_is_auto(self):
        c = self._config_with()
        self.assertEqual(c.http_api_require_auth, 'auto')

    def test_aliases_resolve_to_true(self):
        for raw in ('true', 'TRUE', '1', 'yes', 'YES', 'on', '  on  '):
            with self.subTest(raw=raw):
                c = self._config_with(HTTP_API_REQUIRE_AUTH=raw)
                self.assertEqual(c.http_api_require_auth, 'true')

    def test_aliases_resolve_to_false(self):
        for raw in ('false', 'FALSE', '0', 'no', 'NO', 'off'):
            with self.subTest(raw=raw):
                c = self._config_with(HTTP_API_REQUIRE_AUTH=raw)
                self.assertEqual(c.http_api_require_auth, 'false')

    def test_unknown_value_falls_back_to_auto(self):
        c = self._config_with(HTTP_API_REQUIRE_AUTH='maybe')
        self.assertEqual(c.http_api_require_auth, 'auto')

    def test_auto_loopback_bind_no_key_does_not_require(self):
        c = self._config_with(HTTP_API_BIND='127.0.0.1')
        self.assertFalse(c.http_api_auth_required())

    def test_auto_localhost_bind_no_key_does_not_require(self):
        c = self._config_with(HTTP_API_BIND='localhost')
        self.assertFalse(c.http_api_auth_required())

    def test_auto_ipv6_loopback_bind_no_key_does_not_require(self):
        c = self._config_with(HTTP_API_BIND='::1')
        self.assertFalse(c.http_api_auth_required())

    def test_auto_non_loopback_bind_requires(self):
        c = self._config_with(HTTP_API_BIND='0.0.0.0')
        self.assertTrue(c.http_api_auth_required())

    def test_auto_non_loopback_lan_bind_requires(self):
        c = self._config_with(HTTP_API_BIND='10.0.0.5')
        self.assertTrue(c.http_api_auth_required())

    def test_explicit_true_requires_even_on_loopback(self):
        c = self._config_with(HTTP_API_BIND='127.0.0.1', HTTP_API_REQUIRE_AUTH='true')
        self.assertTrue(c.http_api_auth_required())

    def test_explicit_false_does_not_require_even_on_lan(self):
        c = self._config_with(HTTP_API_BIND='0.0.0.0', HTTP_API_REQUIRE_AUTH='false')
        self.assertFalse(c.http_api_auth_required())


class TestValidateConfigHttpApiAuth(unittest.TestCase):
    """validate_config behavior across the HTTP_API_REQUIRE_AUTH matrix."""

    @staticmethod
    def _write_config(extra: str = "") -> str:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("VPN_PROVIDER=pia\n")
            f.write("PIA_USER=u\n")
            f.write("PIA_PASS=p\n")
            f.write("HTTP_API_ENABLED=true\n")
            f.write(extra)
            return f.name

    def test_auto_lan_bind_no_key_is_error(self):
        """The flagship case: default policy refuses unauth API on a LAN bind."""
        path = self._write_config("HTTP_API_BIND=0.0.0.0\n")
        try:
            is_valid, issues = validate_config(path)
            self.assertFalse(is_valid)
            self.assertTrue(
                any("HTTP_API_KEY" in i and not i.startswith("Warning:") for i in issues),
                f"expected an error mentioning HTTP_API_KEY, got: {issues}",
            )
        finally:
            os.unlink(path)

    def test_auto_loopback_no_key_is_valid(self):
        """Loopback-only bind without a key is allowed under auto policy."""
        path = self._write_config("HTTP_API_BIND=127.0.0.1\n")
        try:
            is_valid, issues = validate_config(path)
            self.assertTrue(is_valid, f"expected valid, got issues: {issues}")
            self.assertFalse(
                any("HTTP_API_KEY" in i for i in issues),
                f"did not expect HTTP_API_KEY issues, got: {issues}",
            )
        finally:
            os.unlink(path)

    def test_auto_lan_bind_with_key_is_valid(self):
        """LAN bind with a key set satisfies the policy."""
        path = self._write_config("HTTP_API_BIND=0.0.0.0\nHTTP_API_KEY=xyz\n")
        try:
            is_valid, issues = validate_config(path)
            self.assertTrue(is_valid, f"expected valid, got issues: {issues}")
            self.assertFalse(any("HTTP_API_KEY" in i for i in issues))
        finally:
            os.unlink(path)

    def test_explicit_false_lan_bind_no_key_is_warning_not_error(self):
        """Explicit opt-out is allowed but logged as a warning."""
        path = self._write_config(
            "HTTP_API_BIND=0.0.0.0\nHTTP_API_REQUIRE_AUTH=false\n"
        )
        try:
            is_valid, issues = validate_config(path)
            self.assertTrue(is_valid, f"expected valid, got issues: {issues}")
            self.assertTrue(
                any(i.startswith("Warning:") and "HTTP_API_REQUIRE_AUTH" in i for i in issues),
                f"expected a warning, got: {issues}",
            )
        finally:
            os.unlink(path)

    def test_explicit_true_loopback_no_key_is_error(self):
        """Strict mode requires a key even on loopback."""
        path = self._write_config(
            "HTTP_API_BIND=127.0.0.1\nHTTP_API_REQUIRE_AUTH=true\n"
        )
        try:
            is_valid, issues = validate_config(path)
            self.assertFalse(is_valid)
            self.assertTrue(
                any("HTTP_API_KEY" in i and not i.startswith("Warning:") for i in issues)
            )
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
