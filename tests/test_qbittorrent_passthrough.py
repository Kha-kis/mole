"""Tests for qBittorrent passthrough modes and managed artifacts."""

import argparse
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mole_pkg.cli import (
    _qbittorrent_passthrough,
    _qbittorrent_passthrough_dependency,
    _qbittorrent_passthrough_executable,
    _qbittorrent_passthrough_service_content,
    _qbittorrent_passthrough_wrapper_content,
)
from mole_pkg.config import Config, validate_config


class TestPassthroughConfig(unittest.TestCase):
    def _config(self, content: str) -> Config:
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False)
        handle.write(content)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return Config(handle.name)

    def test_default_mode_is_socat(self):
        self.assertEqual(self._config("").qb_passthrough_mode, "socat")

    def test_mode_is_normalized(self):
        config = self._config("QB_PASSTHROUGH_MODE= NGINX \n")
        self.assertEqual(config.qb_passthrough_mode, "nginx")

    def test_invalid_mode_fails_validation(self):
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False)
        handle.write(
            "VPN_PROVIDER=pia\n"
            "PIA_USER=test\n"
            "PIA_PASS=test\n"
            "QB_PASSTHROUGH_MODE=haproxy\n"
        )
        handle.close()
        self.addCleanup(os.unlink, handle.name)

        _, issues = validate_config(handle.name)

        self.assertTrue(
            any("QB_PASSTHROUGH_MODE" in issue and "socat, nginx" in issue for issue in issues),
            issues,
        )

    def test_security_options_default_to_disabled(self):
        config = self._config("")
        self.assertEqual(config.qb_passthrough_allowed_cidrs, "")
        self.assertEqual(config.qb_passthrough_upstream_auth_file, "")

    def test_security_options_are_loaded(self):
        config = self._config(
            "QB_PASSTHROUGH_ALLOWED_CIDRS=172.26.0.0/24, 172.26.0.10/32\n"
            "QB_PASSTHROUGH_UPSTREAM_AUTH_FILE=/etc/mole/qbittorrent-upstream.auth\n"
        )
        self.assertEqual(
            config.qb_passthrough_allowed_cidrs,
            "172.26.0.0/24, 172.26.0.10/32",
        )
        self.assertEqual(
            config.qb_passthrough_upstream_auth_file,
            "/etc/mole/qbittorrent-upstream.auth",
        )
        self.assertEqual(
            config.qb_api_auth_file,
            "/etc/mole/qbittorrent-upstream.auth",
        )

    def test_malformed_api_auth_file_fails_validation(self):
        auth_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
        auth_file.write("missing-password-separator\n")
        auth_file.close()
        self.addCleanup(os.unlink, auth_file.name)

        config_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
        config_file.write(
            "VPN_PROVIDER=pia\n"
            "PIA_USER=test\n"
            "PIA_PASS=test\n"
            f"QB_API_AUTH_FILE={auth_file.name}\n"
        )
        config_file.close()
        self.addCleanup(os.unlink, config_file.name)

        _, issues = validate_config(config_file.name)

        self.assertTrue(
            any("QB_API_AUTH_FILE" in issue and "username:password" in issue for issue in issues),
            issues,
        )

    def test_invalid_allowed_cidr_fails_validation(self):
        handle = tempfile.NamedTemporaryFile(mode="w", delete=False)
        handle.write(
            "VPN_PROVIDER=pia\n"
            "PIA_USER=test\n"
            "PIA_PASS=test\n"
            "QB_PASSTHROUGH_MODE=nginx\n"
            "QB_PASSTHROUGH_ALLOWED_CIDRS=172.26.0.0/24,not-a-subnet\n"
        )
        handle.close()
        self.addCleanup(os.unlink, handle.name)

        _, issues = validate_config(handle.name)

        self.assertTrue(
            any(
                "QB_PASSTHROUGH_ALLOWED_CIDRS" in issue
                and "not-a-subnet" in issue
                for issue in issues
            ),
            issues,
        )


class TestPassthroughArtifacts(unittest.TestCase):
    def test_dependency_matches_mode(self):
        config = MagicMock(qb_passthrough_mode="nginx")
        self.assertEqual(_qbittorrent_passthrough_dependency(config), "nginx")
        config.qb_passthrough_mode = "socat"
        self.assertEqual(_qbittorrent_passthrough_dependency(config), "socat")

    @patch("mole_pkg.cli.shutil.which", return_value="/usr/sbin/nginx")
    def test_dependency_search_includes_system_sbin(self, mock_which):
        config = MagicMock(qb_passthrough_mode="nginx")

        self.assertEqual(_qbittorrent_passthrough_executable(config), "/usr/sbin/nginx")
        search_path = mock_which.call_args.kwargs["path"].split(os.pathsep)
        self.assertIn("/usr/sbin", search_path)

    def test_wrapper_preserves_socat_mode(self):
        wrapper = _qbittorrent_passthrough_wrapper_content()
        self.assertIn('if [[ -r "$CONFIG_FILE" ]]; then', wrapper)
        self.assertIn('QB_PASSTHROUGH_MODE_RUN="${QB_PASSTHROUGH_MODE:-socat}"', wrapper)
        self.assertIn('TCP-LISTEN:${QB_PORT_RUN}', wrapper)
        self.assertIn('TCP:${VETH_VPN_IP_RUN}:${QB_PORT_RUN}', wrapper)

    def test_wrapper_has_valid_bash_syntax(self):
        result = subprocess.run(
            ["bash", "-n"],
            input=_qbittorrent_passthrough_wrapper_content(),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_wrapper_generates_http_aware_nginx_proxy(self):
        wrapper = _qbittorrent_passthrough_wrapper_content()
        required_directives = (
            "proxy_http_version 1.1;",
            "proxy_set_header Connection close;",
            "proxy_set_header Host ${VETH_VPN_IP_RUN}:${QB_PORT_RUN};",
            "client_max_body_size 64m;",
            "proxy_request_buffering off;",
            "proxy_buffering off;",
            "proxy_connect_timeout 5s;",
            "proxy_send_timeout 100s;",
            "proxy_read_timeout 100s;",
        )
        for directive in required_directives:
            self.assertIn(directive, wrapper)
        self.assertIn("daemon off;", wrapper)
        self.assertIn("error_log stderr notice;", wrapper)
        self.assertIn("access_log off;", wrapper)

    def test_nginx_mode_renders_allowlist_and_upstream_basic_auth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wrapper = root / "passthrough.sh"
            config = root / "mole.conf"
            auth_file = root / "qbit.auth"
            bin_dir = root / "bin"
            runtime_dir = root / "run"
            bin_dir.mkdir()
            runtime_dir.mkdir()

            wrapper.write_text(_qbittorrent_passthrough_wrapper_content())
            wrapper.chmod(0o755)
            auth_file.write_text("service-user:correct horse battery staple\n")
            config.write_text(
                "QB_PORT=10048\n"
                "VETH_VPN_IP=10.200.200.2\n"
                "QB_PASSTHROUGH_BIND=172.26.0.1\n"
                "QB_PASSTHROUGH_MODE=nginx\n"
                "QB_PASSTHROUGH_ALLOWED_CIDRS=172.26.0.0/24,172.26.1.10/32\n"
                f"QB_PASSTHROUGH_UPSTREAM_AUTH_FILE={auth_file}\n"
            )

            fake_nginx = bin_dir / "nginx"
            fake_nginx.write_text(
                "#!/bin/bash\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  if [[ $1 == -c ]]; then cat \"$2\"; exit 0; fi\n"
                "  shift\n"
                "done\n"
                "exit 1\n"
            )
            fake_nginx.chmod(0o755)

            result = subprocess.run(
                [str(wrapper)],
                capture_output=True,
                text=True,
                env={
                    "MOLE_CONFIG": str(config),
                    "RUNTIME_DIRECTORY": str(runtime_dir),
                    "PATH": f"{bin_dir}:/usr/bin:/bin",
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("allow 172.26.0.0/24;", result.stdout)
            self.assertIn("allow 172.26.1.10/32;", result.stdout)
            self.assertIn("deny all;", result.stdout)
            self.assertIn("proxy_set_header Authorization \"Basic ", result.stdout)
            self.assertNotIn("correct horse battery staple", result.stdout)

    def test_nginx_mode_rejects_invalid_runtime_cidr(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wrapper = root / "passthrough.sh"
            config = root / "mole.conf"
            wrapper.write_text(_qbittorrent_passthrough_wrapper_content())
            wrapper.chmod(0o755)
            config.write_text(
                "QB_PASSTHROUGH_MODE=nginx\n"
                "QB_PASSTHROUGH_ALLOWED_CIDRS=172.26.0.0/99\n"
            )

            result = subprocess.run(
                [str(wrapper)],
                capture_output=True,
                text=True,
                env={
                    "MOLE_CONFIG": str(config),
                    "RUNTIME_DIRECTORY": str(root / "run"),
                    "PATH": "/usr/bin:/bin",
                },
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("Invalid QB_PASSTHROUGH_ALLOWED_CIDRS", result.stderr)

    def test_nginx_mode_renders_runtime_config_with_selected_addresses(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            wrapper = root / "passthrough.sh"
            config = root / "mole.conf"
            bin_dir = root / "bin"
            runtime_dir = root / "run"
            bin_dir.mkdir()
            runtime_dir.mkdir()

            wrapper.write_text(_qbittorrent_passthrough_wrapper_content())
            wrapper.chmod(0o755)
            config.write_text(
                "QB_PORT=10048\n"
                "VETH_VPN_IP=10.200.200.2\n"
                "QB_PASSTHROUGH_BIND=172.24.0.1\n"
                "QB_PASSTHROUGH_MODE=nginx\n"
            )

            fake_nginx = bin_dir / "nginx"
            fake_nginx.write_text(
                "#!/bin/bash\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  if [[ $1 == -c ]]; then cat \"$2\"; exit 0; fi\n"
                "  shift\n"
                "done\n"
                "exit 1\n"
            )
            fake_nginx.chmod(0o755)

            result = subprocess.run(
                [str(wrapper)],
                capture_output=True,
                text=True,
                env={
                    "MOLE_CONFIG": str(config),
                    "RUNTIME_DIRECTORY": str(runtime_dir),
                    "PATH": f"{bin_dir}:/usr/bin:/bin",
                },
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("listen 172.24.0.1:10048;", result.stdout)
            self.assertIn("proxy_pass http://10.200.200.2:10048;", result.stdout)
            self.assertIn("proxy_set_header Host 10.200.200.2:10048;", result.stdout)

    def test_service_executes_wrapper_with_private_runtime_directory(self):
        service = _qbittorrent_passthrough_service_content()
        self.assertIn("DynamicUser=yes", service)
        self.assertIn("EnvironmentFile=-/etc/mole/config", service)
        self.assertIn("RuntimeDirectory=qbittorrent-passthrough", service)
        self.assertIn("ExecStart=/usr/local/lib/mole/qbittorrent-passthrough.sh", service)
        self.assertNotIn("ExecStart=/usr/bin/socat", service)

    def test_service_applies_security_sandbox(self):
        service = _qbittorrent_passthrough_service_content()
        required_directives = (
            "NoNewPrivileges=yes",
            "PrivateDevices=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "ProtectKernelTunables=yes",
            "ProtectKernelModules=yes",
            "ProtectControlGroups=yes",
            "ProtectKernelLogs=yes",
            "ProtectClock=yes",
            "ProtectHostname=yes",
            "RestrictSUIDSGID=yes",
            "LockPersonality=yes",
            "MemoryDenyWriteExecute=yes",
            "RestrictRealtime=yes",
            "RestrictNamespaces=yes",
            "SystemCallArchitectures=native",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            "CapabilityBoundingSet=",
            "UMask=0077",
        )
        for directive in required_directives:
            self.assertIn(directive, service)


class TestPassthroughReconciliation(unittest.TestCase):
    @patch("mole_pkg.cli._qbittorrent_setup_services", return_value=True)
    @patch("mole_pkg.cli.shutil.which", return_value="/usr/sbin/nginx")
    @patch("mole_pkg.cli.Config")
    @patch("mole_pkg.cli.Path")
    @patch("mole_pkg.cli.subprocess.run")
    @patch("mole_pkg.cli.os.geteuid", return_value=0)
    def test_existing_service_is_reconciled(
        self,
        _mock_euid,
        mock_run,
        mock_path,
        mock_config,
        _mock_which,
        mock_setup,
    ):
        mock_config.return_value.qb_passthrough_mode = "nginx"
        mock_config.return_value.qb_port = 10048
        mock_config.return_value.qb_passthrough_bind = "172.24.0.1"
        mock_path.return_value.exists.return_value = True
        mock_run.return_value = MagicMock(returncode=0, stdout="active\n")

        result = _qbittorrent_passthrough(argparse.Namespace())

        self.assertEqual(result, 0)
        mock_setup.assert_called_once_with(enable_passthrough=True, verbose=True)


if __name__ == "__main__":
    unittest.main()
