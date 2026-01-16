"""
Tests for mole_pkg.providers module
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import tempfile
import os

from mole_pkg.providers import PIAProvider, ProtonProvider
from mole_pkg.providers.pia import apply_region_to_config
from mole_pkg.utils import VPNState


class TestPIAProviderImport(unittest.TestCase):
    """Test that PIA provider can be imported"""

    def test_import_provider(self):
        """PIAProvider can be imported"""
        from mole_pkg.providers import PIAProvider
        self.assertTrue(callable(PIAProvider))


class TestPIAProviderProperties(unittest.TestCase):
    """Test PIAProvider properties"""

    def setUp(self):
        """Create mock config and state"""
        self.mock_config = Mock()
        self.mock_config.get.return_value = ""
        self.mock_config.config_dir = "/etc/mole"
        self.mock_config.port_forward = True

        self.state = VPNState()
        self.provider = PIAProvider(self.mock_config, self.state)

    def test_name_property(self):
        """Provider name is PIA"""
        self.assertEqual(self.provider.name, "PIA")

    def test_ca_cert_path(self):
        """CA cert path is correct"""
        self.assertEqual(self.provider._ca_cert, "/etc/mole/providers/pia-ca.crt")

    def test_regions_empty(self):
        """Regions returns empty list when not configured"""
        self.mock_config.get.return_value = ""
        self.assertEqual(self.provider._regions, [])

    def test_regions_single(self):
        """Regions parses single region"""
        self.mock_config.get.return_value = "us_east"
        self.assertEqual(self.provider._regions, ["us_east"])

    def test_regions_multiple(self):
        """Regions parses comma-separated regions"""
        self.mock_config.get.return_value = "us_east, us_west, ca_toronto"
        self.assertEqual(self.provider._regions, ["us_east", "us_west", "ca_toronto"])


class TestApplyRegionToConfig(unittest.TestCase):
    """Test apply_region_to_config function"""

    def test_apply_region_updates_config(self):
        """apply_region_to_config updates config file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("VPN_PROVIDER=pia\n")
            f.write("PIA_REGION=old_region\n")
            temp_path = f.name

        try:
            # Patch the DEFAULT_CONFIG_FILE to use our temp file
            with patch('mole_pkg.providers.pia.DEFAULT_CONFIG_FILE', temp_path):
                result = apply_region_to_config("new_region")

            self.assertTrue(result)
            content = open(temp_path).read()
            self.assertIn("PIA_REGION=new_region", content)
            self.assertNotIn("PIA_REGION=old_region", content)
        finally:
            os.unlink(temp_path)

    def test_apply_region_adds_if_missing(self):
        """apply_region_to_config adds region if not present"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("VPN_PROVIDER=pia\n")
            temp_path = f.name

        try:
            with patch('mole_pkg.providers.pia.DEFAULT_CONFIG_FILE', temp_path):
                result = apply_region_to_config("new_region")

            self.assertTrue(result)
            content = open(temp_path).read()
            self.assertIn("PIA_REGION=new_region", content)
        finally:
            os.unlink(temp_path)

    def test_apply_region_with_server(self):
        """apply_region_to_config can set server hostname"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            f.write("VPN_PROVIDER=pia\n")
            f.write("PIA_REGION=old_region\n")
            temp_path = f.name

        try:
            with patch('mole_pkg.providers.pia.DEFAULT_CONFIG_FILE', temp_path):
                result = apply_region_to_config("new_region", "server.example.com")

            self.assertTrue(result)
            content = open(temp_path).read()
            self.assertIn("PIA_REGION=new_region", content)
            self.assertIn("PIA_SERVER=server.example.com", content)
        finally:
            os.unlink(temp_path)


class TestPortForwardPersistence(unittest.TestCase):
    """Test port forwarding persistence feature"""

    def setUp(self):
        """Create mock config and state"""
        self.temp_dir = tempfile.mkdtemp()
        self.mock_config = Mock()
        self.mock_config.get.return_value = ""
        self.mock_config.config_dir = "/etc/mole"
        self.mock_config.state_dir = self.temp_dir
        self.mock_config.port_forward = True
        self.mock_config.netns = "vpn"

        self.state = VPNState()
        self.state.server_hostname = "test-server.example.com"
        self.state.server_vip = "10.0.0.1"
        self.provider = PIAProvider(self.mock_config, self.state)

    def tearDown(self):
        """Clean up temp directory"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_saved_port_forward_no_file(self):
        """Returns False when no saved state exists"""
        result = self.provider._load_saved_port_forward()
        self.assertFalse(result)

    def test_load_saved_port_forward_valid(self):
        """Loads valid saved port forward state"""
        import base64
        import json
        from datetime import datetime, timedelta, timezone

        # Create valid payload (expires in 30 days)
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        port_data = {
            "port": 12345,
            "expires_at": expires_at.isoformat().replace("+00:00", "Z")
        }
        payload = base64.b64encode(json.dumps(port_data).encode()).decode()

        pf_response = {
            "status": "OK",
            "payload": payload,
            "signature": "test_signature",
            "server_hostname": "test-server.example.com"
        }

        # Save to file
        pf_file = os.path.join(self.temp_dir, "pf-response.json")
        with open(pf_file, 'w') as f:
            json.dump(pf_response, f)

        # Load and verify
        result = self.provider._load_saved_port_forward()
        self.assertTrue(result)
        self.assertEqual(self.state.port, 12345)
        self.assertEqual(self.state.port_payload, payload)
        self.assertEqual(self.state.port_signature, "test_signature")

    def test_load_saved_port_forward_expired(self):
        """Returns False when saved state is expired"""
        import base64
        import json
        from datetime import datetime, timedelta, timezone

        # Create expired payload
        expires_at = datetime.now(timezone.utc) - timedelta(days=1)
        port_data = {
            "port": 12345,
            "expires_at": expires_at.isoformat().replace("+00:00", "Z")
        }
        payload = base64.b64encode(json.dumps(port_data).encode()).decode()

        pf_response = {
            "status": "OK",
            "payload": payload,
            "signature": "test_signature"
        }

        # Save to file
        pf_file = os.path.join(self.temp_dir, "pf-response.json")
        with open(pf_file, 'w') as f:
            json.dump(pf_response, f)

        # Load and verify it's rejected
        result = self.provider._load_saved_port_forward()
        self.assertFalse(result)

    def test_load_saved_port_forward_server_change_logged(self):
        """Logs when server changed but still loads state"""
        import base64
        import json
        from datetime import datetime, timedelta, timezone

        # Create valid payload with different server
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        port_data = {
            "port": 12345,
            "expires_at": expires_at.isoformat().replace("+00:00", "Z")
        }
        payload = base64.b64encode(json.dumps(port_data).encode()).decode()

        pf_response = {
            "status": "OK",
            "payload": payload,
            "signature": "test_signature",
            "server_hostname": "old-server.example.com"  # Different server
        }

        # Save to file
        pf_file = os.path.join(self.temp_dir, "pf-response.json")
        with open(pf_file, 'w') as f:
            json.dump(pf_response, f)

        # Should still load (PIA allows cross-server binding)
        result = self.provider._load_saved_port_forward()
        self.assertTrue(result)
        self.assertEqual(self.state.port, 12345)


class TestProtonProviderImport(unittest.TestCase):
    """Test that Proton provider can be imported"""

    def test_import_provider(self):
        """ProtonProvider can be imported"""
        from mole_pkg.providers import ProtonProvider
        self.assertTrue(callable(ProtonProvider))


class TestProtonProviderProperties(unittest.TestCase):
    """Test ProtonProvider properties"""

    def setUp(self):
        """Create mock config and state"""
        self.temp_dir = tempfile.mkdtemp()
        self.mock_config = Mock()
        self.mock_config.get.return_value = ""
        self.mock_config.state_dir = self.temp_dir
        self.mock_config.port_forward = True

        self.state = VPNState()
        self.provider = ProtonProvider(self.mock_config, self.state)

    def tearDown(self):
        """Clean up temp directory"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_name_property(self):
        """Provider name is ProtonVPN"""
        self.assertEqual(self.provider.name, "ProtonVPN")

    def test_tier_default(self):
        """Default tier is 2 (Plus)"""
        self.mock_config.get.return_value = ""
        self.assertEqual(self.provider._tier, 2)

    def test_tier_configured(self):
        """Tier is parsed from config"""
        def get_side_effect(key, default=''):
            if key == 'PROTON_TIER':
                return '1'
            return default
        self.mock_config.get.side_effect = get_side_effect
        self.assertEqual(self.provider._tier, 1)

    def test_countries_empty_when_not_configured(self):
        """Countries is empty list when not configured"""
        self.mock_config.get.return_value = ""
        self.assertEqual(self.provider._countries, [])

    def test_countries_single(self):
        """Single country is parsed from config"""
        def get_side_effect(key, default=''):
            if key == 'PROTON_COUNTRY':
                return 'us'
            return default
        self.mock_config.get.side_effect = get_side_effect
        self.assertEqual(self.provider._countries, ['US'])

    def test_countries_multiple(self):
        """Multiple countries parsed from comma-separated config"""
        def get_side_effect(key, default=''):
            if key == 'PROTON_COUNTRY':
                return 'NL, DE, CH'
            return default
        self.mock_config.get.side_effect = get_side_effect
        self.assertEqual(self.provider._countries, ['NL', 'DE', 'CH'])

    def test_natpmp_gateway_default(self):
        """Default NAT-PMP gateway is 10.2.0.1"""
        def get_side_effect(key, default=''):
            if key == 'PROTON_NATPMP_GATEWAY':
                return default  # Return the default value
            return ''
        self.mock_config.get.side_effect = get_side_effect
        self.assertEqual(self.provider._natpmp_gateway, '10.2.0.1')


class TestProtonServerFiltering(unittest.TestCase):
    """Test ProtonProvider server filtering"""

    def setUp(self):
        """Create mock config and state"""
        self.temp_dir = tempfile.mkdtemp()
        self.mock_config = Mock()
        self.mock_config.get.return_value = ""
        self.mock_config.state_dir = self.temp_dir
        self.mock_config.port_forward = False

        self.state = VPNState()
        self.provider = ProtonProvider(self.mock_config, self.state)

    def tearDown(self):
        """Clean up temp directory"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_filter_disabled_servers(self):
        """Disabled servers are filtered out"""
        servers = [
            {"Status": 0, "Tier": 2, "Servers": [{"X25519PublicKey": "key1", "EntryIP": "1.2.3.4"}]},
            {"Status": 1, "Tier": 2, "Name": "Active", "Domain": "active.protonvpn.net",
             "ExitCountry": "US", "Features": 0, "Load": 50,
             "Servers": [{"X25519PublicKey": "key2", "EntryIP": "5.6.7.8"}]},
        ]
        filtered = self.provider._filter_servers(servers)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["name"], "Active")

    def test_filter_by_tier(self):
        """Servers above user tier are filtered out"""
        # Set tier to 1 (basic), disable P2P preference
        def get_side_effect(key, default=''):
            if key == 'PROTON_TIER':
                return '1'
            if key == 'PROTON_PREFER_P2P':
                return 'false'
            return default
        self.mock_config.get.side_effect = get_side_effect

        servers = [
            {"Status": 1, "Tier": 2, "Name": "Plus", "Domain": "plus.protonvpn.net",
             "ExitCountry": "US", "Features": 0, "Load": 50,
             "Servers": [{"X25519PublicKey": "key1", "EntryIP": "1.2.3.4"}]},
            {"Status": 1, "Tier": 1, "Name": "Basic", "Domain": "basic.protonvpn.net",
             "ExitCountry": "US", "Features": 0, "Load": 50,
             "Servers": [{"X25519PublicKey": "key2", "EntryIP": "5.6.7.8"}]},
        ]
        filtered = self.provider._filter_servers(servers)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["name"], "Basic")

    def test_filter_by_country(self):
        """Servers in wrong country are filtered out when country parameter passed"""
        def get_side_effect(key, default=''):
            if key == 'PROTON_PREFER_P2P':
                return 'false'
            return default
        self.mock_config.get.side_effect = get_side_effect

        servers = [
            {"Status": 1, "Tier": 2, "Name": "US Server", "Domain": "us.protonvpn.net",
             "ExitCountry": "US", "Features": 0, "Load": 50,
             "Servers": [{"X25519PublicKey": "key1", "EntryIP": "1.2.3.4"}]},
            {"Status": 1, "Tier": 2, "Name": "CH Server", "Domain": "ch.protonvpn.net",
             "ExitCountry": "CH", "Features": 0, "Load": 50,
             "Servers": [{"X25519PublicKey": "key2", "EntryIP": "5.6.7.8"}]},
        ]
        # Pass country as parameter (new signature)
        filtered = self.provider._filter_servers(servers, country='CH')
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["name"], "CH Server")

    def test_filter_p2p_when_port_forward(self):
        """Non-P2P servers filtered when port forwarding enabled"""
        self.mock_config.port_forward = True

        servers = [
            {"Status": 1, "Tier": 2, "Name": "No P2P", "Domain": "nop2p.protonvpn.net",
             "ExitCountry": "US", "Features": 0, "Load": 50,  # No P2P (feature bit 4)
             "Servers": [{"X25519PublicKey": "key1", "EntryIP": "1.2.3.4"}]},
            {"Status": 1, "Tier": 2, "Name": "P2P", "Domain": "p2p.protonvpn.net",
             "ExitCountry": "US", "Features": 4, "Load": 50,  # P2P enabled (feature bit 4)
             "Servers": [{"X25519PublicKey": "key2", "EntryIP": "5.6.7.8"}]},
        ]
        filtered = self.provider._filter_servers(servers)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["name"], "P2P")


if __name__ == '__main__':
    unittest.main()
