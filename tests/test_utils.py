"""
Tests for mole_pkg.utils module
"""

import os
import tempfile
import unittest
from pathlib import Path

from mole_pkg.utils import (
    VPNState,
    run_cmd,
    secure_write_file,
    sanitize_for_log,
)


class TestVPNState(unittest.TestCase):
    """Test VPNState dataclass"""

    def test_default_values(self):
        """VPNState has correct defaults"""
        state = VPNState()
        self.assertIsNone(state.token)
        self.assertIsNone(state.token_expires)
        self.assertIsNone(state.server_ip)
        self.assertIsNone(state.server_hostname)
        self.assertIsNone(state.server_vip)
        self.assertIsNone(state.peer_ip)
        self.assertIsNone(state.port)
        self.assertIsNone(state.port_payload)
        self.assertIsNone(state.port_signature)
        self.assertIsNone(state.port_expires)
        self.assertFalse(state.connected)

    def test_state_attributes(self):
        """VPNState can be populated"""
        state = VPNState(
            token="testtoken",
            server_ip="1.2.3.4",
            server_hostname="test.server.com",
            port=12345,
            connected=True
        )
        self.assertEqual(state.token, "testtoken")
        self.assertEqual(state.server_ip, "1.2.3.4")
        self.assertEqual(state.server_hostname, "test.server.com")
        self.assertEqual(state.port, 12345)
        self.assertTrue(state.connected)


class TestRunCmd(unittest.TestCase):
    """Test run_cmd function"""

    def test_successful_command(self):
        """run_cmd returns successful result"""
        result = run_cmd(["echo", "hello"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("hello", result.stdout)

    def test_failed_command_no_check(self):
        """run_cmd returns failed result when check=False"""
        result = run_cmd(["false"], check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_command_with_output(self):
        """run_cmd captures stdout"""
        result = run_cmd(["echo", "test output"])
        self.assertIn("test output", result.stdout)


class TestSecureWriteFile(unittest.TestCase):
    """Test secure_write_file function"""

    def test_write_file(self):
        """secure_write_file creates file with content"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "testfile"
            secure_write_file(path, "test content")

            self.assertTrue(path.exists())
            self.assertEqual(path.read_text(), "test content")

    def test_file_permissions(self):
        """secure_write_file sets correct permissions"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "testfile"
            secure_write_file(path, "secret", mode=0o600)

            # Check file mode (last 3 digits)
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_custom_permissions(self):
        """secure_write_file respects custom mode"""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "testfile"
            secure_write_file(path, "content", mode=0o640)

            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o640)


class TestSanitizeForLog(unittest.TestCase):
    """Test sanitize_for_log function"""

    def test_empty_string(self):
        """sanitize_for_log handles empty string"""
        self.assertEqual(sanitize_for_log(""), "")

    def test_short_string(self):
        """sanitize_for_log returns short strings unchanged (if no secrets)"""
        result = sanitize_for_log("hello world")
        self.assertEqual(result, "hello world")

    def test_truncate_long_string(self):
        """sanitize_for_log truncates long strings"""
        # Use a string with spaces so it won't match the token redaction pattern
        long_string = "hello world " * 50
        result = sanitize_for_log(long_string, max_length=100)
        self.assertTrue(len(result) < len(long_string))
        self.assertIn("truncated", result)

    def test_redact_long_token(self):
        """sanitize_for_log redacts long alphanumeric strings"""
        text = "token=AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd"
        result = sanitize_for_log(text)
        self.assertIn("[REDACTED]", result)

    def test_redact_json_password(self):
        """sanitize_for_log redacts password in JSON"""
        text = '{"password": "mysecretpassword123"}'
        result = sanitize_for_log(text)
        self.assertIn("[REDACTED]", result)
        self.assertNotIn("mysecretpassword123", result)

    def test_redact_json_token(self):
        """sanitize_for_log redacts token in JSON"""
        text = '{"token": "abc123def456"}'
        result = sanitize_for_log(text)
        self.assertIn("[REDACTED]", result)


if __name__ == '__main__':
    unittest.main()
