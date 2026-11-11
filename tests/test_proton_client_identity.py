import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mole_pkg.providers import proton


class ProtonClientIdentity(unittest.TestCase):
    def test_constructor_uses_current_identity(self):
        with patch.object(proton, 'ProtonAPISession') as api:
            proton.ProtonSessionWrapper(Path('/unused'))._create_session()
        self.assertEqual(api.call_args.kwargs['appversion'], 'linux-vpn@4.19.0')
        self.assertEqual(api.call_args.kwargs['user_agent'], 'ProtonVPN/4.19.0 (Linux)')

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
