import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from mole_pkg.config import Config
from mole_pkg.utils import VPNState
from proton.exceptions import ProtonError

from mole_pkg.providers import proton


class ProtonClientIdentity(unittest.TestCase):
    def test_default_identity_is_verified_version(self):
        with patch.object(proton, 'ProtonAPISession') as api:
            proton.ProtonSessionWrapper(Path('/unused'))._create_session()
        self.assertEqual(api.call_args.kwargs['appversion'], 'linux-vpn@4.19.1')
        self.assertEqual(api.call_args.kwargs['user_agent'], 'ProtonVPN/4.19.1 (Linux)')

    def test_override_applies_to_new_and_loaded_session(self):
        saved = {'session_data': {'AccessToken': 'synthetic'}, 'cookies': {'a': 'b'}}
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'session.json'
            path.write_text(json.dumps(saved))
            with patch.object(proton, 'ProtonAPISession') as api:
                session = proton.ProtonSessionWrapper(path, '4.20.2')
                session._create_session()
                self.assertEqual(api.call_args.kwargs['appversion'], 'linux-vpn@4.20.2')
                self.assertTrue(session.load())
                loaded = api.load.call_args.args[0]
                self.assertEqual(loaded['User-Agent'], 'ProtonVPN/4.20.2 (Linux)')
                self.assertEqual(loaded['session_data'], saved['session_data'])
                self.assertEqual(loaded['cookies'], saved['cookies'])
                self.assertEqual(json.loads(path.read_text()), saved)

    def test_invalid_identity_rejected(self):
        for value in ('', '4.19.1\ninjected', 'linux-vpn@4.19.1', 'https://example.org', '4.19'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                proton.ProtonSessionWrapper(Path('/unused'), value)

    def test_config_identity_default_and_validation(self):
        config = Config('/nonexistent')
        self.assertEqual(config.proton_client_version, '4.19.1')
        config._data['PROTON_CLIENT_VERSION'] = '4.20.2'
        self.assertEqual(config.proton_client_version, '4.20.2')
        config._data['PROTON_CLIENT_VERSION'] = ''
        with self.assertRaises(ValueError):
            config.proton_client_version

    def test_rejection_is_not_retried_and_logs_no_secrets(self):
        wrapper = proton.ProtonSessionWrapper(Path('/unused'))
        with patch.object(proton, 'ProtonAPISession') as api, self.assertLogs(proton.log, 'ERROR') as logs:
            api.return_value.authenticate.side_effect = ProtonError({'Code': 5003, 'Error': 'synthetic-password synthetic-token'})
            self.assertFalse(wrapper.authenticate('synthetic-user', 'synthetic-password'))
            self.assertEqual(api.return_value.authenticate.call_count, 1)
        self.assertTrue(wrapper.compatibility_rejected)
        self.assertNotIn('synthetic-password', str(logs.output))
        self.assertNotIn('synthetic-token', str(logs.output))


class ProtonCompatibilityRecovery(unittest.IsolatedAsyncioTestCase):
    async def test_rejection_does_not_loop_password_authentication(self):
        with tempfile.TemporaryDirectory() as root:
            config = Config('/nonexistent')
            config._data.update(STATE_DIR=root, PROTON_USER='synthetic-user', PROTON_PASS='synthetic-password')
            path = Path(root) / 'proton_session.json'
            path.write_text('{}')
            with patch.object(proton, 'ProtonAPISession') as api, self.assertLogs(proton.log, 'WARNING') as logs:
                api.load.return_value.refresh.side_effect = ProtonError({'Code': 5003, 'Error': 'synthetic-token'})
                provider = proton.ProtonProvider(config, VPNState())
                self.assertFalse(await provider.authenticate())
                api.return_value.authenticate.assert_not_called()
            self.assertNotIn('synthetic-token', str(logs.output))
            self.assertEqual(path.read_text(), '{}')

    def test_load_decodes_and_updates_identity_without_mutating_credentials(self):
        saved = {'api_url': proton.PROTON_API_URL, 'appversion': 'LinuxVPN_4.4.2',
                 'User-Agent': 'old', 'session_data': {'AccessToken': 'synthetic'},
                 'cookies': {'synthetic': 'cookie'}}
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'session.json'
            path.write_text(json.dumps(saved))
            with patch.object(proton, 'ProtonAPISession') as api:
                self.assertTrue(proton.ProtonSessionWrapper(path).load())
            loaded = api.load.call_args.args[0]
            self.assertIsInstance(loaded, dict)
            self.assertEqual(loaded['appversion'], proton.PROTON_APP_VERSION)
            self.assertEqual(loaded['User-Agent'], proton.PROTON_USER_AGENT)
            self.assertEqual(loaded['session_data'], saved['session_data'])
            self.assertEqual(loaded['cookies'], saved['cookies'])
            self.assertEqual(json.loads(path.read_text()), saved)

    def test_invalid_json_rejects_without_loading(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'session.json'
            path.write_text('invalid')
            with patch.object(proton, 'ProtonAPISession') as api:
                self.assertFalse(proton.ProtonSessionWrapper(path).load())
                api.load.assert_not_called()
