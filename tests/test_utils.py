"""
Tests for mole_pkg.utils module
"""

import os
import tempfile
import unittest
from pathlib import Path

import json

from mole_pkg.utils import (
    VPNState,
    increment_dict_counter,
    read_dict_counter,
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


class TestIncrementDictCounter(unittest.TestCase):
    """Atomic JSON-dict counter helper for labelled Prometheus metrics."""

    def test_creates_file_on_first_increment(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            v = increment_dict_counter(d, "pf.json", "NL", "success")
            self.assertEqual(v, 1)
            data = json.loads((d / "pf.json").read_text())
            self.assertEqual(data, {"NL": {"success": 1}})

    def test_increments_existing_bucket(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            for _ in range(5):
                increment_dict_counter(d, "pf.json", "NL", "success")
            v = increment_dict_counter(d, "pf.json", "NL", "failure")
            self.assertEqual(v, 1)
            data = json.loads((d / "pf.json").read_text())
            self.assertEqual(data["NL"]["success"], 5)
            self.assertEqual(data["NL"]["failure"], 1)

    def test_multiple_keys_isolated(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            increment_dict_counter(d, "pf.json", "NL", "success")
            increment_dict_counter(d, "pf.json", "US", "success")
            increment_dict_counter(d, "pf.json", "US", "success")
            data = json.loads((d / "pf.json").read_text())
            self.assertEqual(data["NL"]["success"], 1)
            self.assertEqual(data["US"]["success"], 2)

    def test_empty_dict_key_falls_back_to_unknown(self):
        # Pre-connect or transient state where server_country isn't
        # populated yet — must not silently drop the count.
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            increment_dict_counter(d, "pf.json", "", "success")
            data = json.loads((d / "pf.json").read_text())
            self.assertEqual(data["unknown"]["success"], 1)

    def test_recovers_from_malformed_file(self):
        # Hand-edit, partial-write, or unrelated content shouldn't make
        # mole's keepalive loop crash on the next increment.
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "pf.json").write_text("{this is not json")
            v = increment_dict_counter(d, "pf.json", "NL", "success")
            self.assertEqual(v, 1)
            data = json.loads((d / "pf.json").read_text())
            self.assertEqual(data, {"NL": {"success": 1}})

    def test_recovers_from_non_dict_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "pf.json").write_text('["not", "a", "dict"]')
            v = increment_dict_counter(d, "pf.json", "NL", "success")
            self.assertEqual(v, 1)

    def test_recovers_from_non_dict_bucket(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "pf.json").write_text('{"NL": "broken"}')
            v = increment_dict_counter(d, "pf.json", "NL", "success")
            self.assertEqual(v, 1)
            data = json.loads((d / "pf.json").read_text())
            self.assertEqual(data["NL"], {"success": 1})


class TestReadDictCounter(unittest.TestCase):

    def test_returns_empty_on_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertEqual(read_dict_counter(Path(tmpdir), "missing.json"), {})

    def test_returns_data_on_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "pf.json").write_text('{"NL": {"success": 5}}')
            self.assertEqual(read_dict_counter(d, "pf.json"), {"NL": {"success": 5}})

    def test_returns_empty_on_malformed(self):
        # Readers must never raise into the scrape path.
        with tempfile.TemporaryDirectory() as tmpdir:
            d = Path(tmpdir)
            (d / "pf.json").write_text("not json")
            self.assertEqual(read_dict_counter(d, "pf.json"), {})


if __name__ == '__main__':
    unittest.main()
