"""Generated-service DNS isolation without touching host services or namespaces."""
import argparse
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mole_pkg import cli
from mole_pkg.config import Config, validate_config


def config(**values):
    result = Config('/nonexistent/mole-unit-test-config')
    result._data.update(values)
    return result


class TestQbittorrentDns(unittest.TestCase):
    def wrapper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'etc/systemd/system').mkdir(parents=True)
            with patch('mole_pkg.cli.Config', return_value=config()), patch(
                'mole_pkg.cli.Path', side_effect=lambda path: root / str(path).lstrip('/')
            ), patch('mole_pkg.cli.subprocess.run'):
                self.assertTrue(cli._qbittorrent_setup_services(verbose=False))
            return (root / 'usr/local/lib/mole/qbittorrent-wrapper.sh').read_text()

    def run_wrapper(self, resolver, environment=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('ip', 'nsenter'):
                executable = root / name
                executable.write_text('#!/bin/bash\nprintf "%s:%s\\n" "${0##*/}" "$*"\n')
                executable.chmod(0o755)
            settings = root / 'config'
            settings.write_text('NETNS_NAME=example-vpn\nQB_DNS_RESOLV_CONF=' + resolver + '\n')
            wrapper = root / 'wrapper.sh'
            wrapper.write_text(self.wrapper().replace('/usr/bin/ip', str(root / 'ip')).replace(
                '/usr/bin/nsenter', str(root / 'nsenter')))
            return subprocess.run(['bash', str(wrapper)], text=True, capture_output=True,
                                  env={**os.environ, 'MOLE_CONFIG': str(settings),
                                       'PATH': str(root) + ':/usr/bin:/bin',
                                       **(environment or {})}, timeout=5)

    def test_prefixed_environment_selection_is_compiled_for_wrapper(self):
        with patch.dict(os.environ, {'MOLE_QB_DNS_RESOLV_CONF': '/etc/example/custom.conf',
                                     'MOLE_NETNS_NAME': 'custom-vpn'}):
            value = Config('/nonexistent/mole-unit-test-config')
        unit = cli._qbittorrent_service_content(value)
        self.assertIn('Environment=MOLE_QBIT_SERVICE_RESOLVER=/etc/example/custom.conf', unit)
        self.assertIn('Environment=MOLE_QBIT_SERVICE_NETNS=custom-vpn', unit)

    def test_wrapper_uses_compiled_selection_even_if_config_setting_is_absent(self):
        result = self.run_wrapper('', {'MOLE_QB_DNS_RESOLV_CONF': '/etc/resolv.conf',
                                      'MOLE_QBIT_SERVICE_RESOLVER': '/etc/resolv.conf',
                                      'MOLE_QBIT_SERVICE_NETNS': 'custom-vpn'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('nsenter:--net=/run/netns/custom-vpn', result.stdout)

    def test_wrapper_rejects_new_request_when_unit_has_no_binding(self):
        result = self.run_wrapper('/etc/resolv.conf', {'MOLE_QBIT_SERVICE_RESOLVER': ''})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('resolver binding', result.stderr)

    def test_explicit_binding_rejects_namespace_unit_injection(self):
        for name in ['bad name', 'bad\nname', 'bad%n', '../other']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                cli._qbittorrent_service_content(config(QB_DNS_RESOLV_CONF='/etc/example/custom.conf',
                                                      NETNS_NAME=name))

    def test_selected_resolver_does_not_get_overlaid_by_ip_netns_exec(self):
        result = self.run_wrapper('/etc/resolv.conf')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('nsenter:--net=/run/netns/example-vpn', result.stdout)

    def test_wrapper_refuses_missing_or_stale_selected_binding(self):
        result = self.run_wrapper('/nonexistent/resolver-fixture.conf')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('resolver binding', result.stderr)

    def test_unset_binding_keeps_legacy_namespace_entry(self):
        result = self.run_wrapper('')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('ip:netns exec example-vpn sudo', result.stdout)

    def test_unset_binding_preserves_existing_installations(self):
        self.assertEqual(config().qb_dns_resolv_conf, '')
        self.assertNotIn('BindReadOnlyPaths=', cli._qbittorrent_service_content(config()))

    def test_auto_binding_uses_configured_namespace(self):
        value = config(QB_DNS_RESOLV_CONF='auto', NETNS_NAME='example-vpn')
        self.assertEqual(value.qb_dns_resolv_conf, '/etc/netns/example-vpn/resolv.conf')
        unit = cli._qbittorrent_service_content(value)
        self.assertIn('BindReadOnlyPaths=/etc/netns/example-vpn/resolv.conf:/etc/resolv.conf', unit)
        self.assertNotIn('BindReadOnlyPaths=-', unit)

    def test_auto_binding_defaults_to_vpn_namespace(self):
        self.assertEqual(config(QB_DNS_RESOLV_CONF='auto').qb_dns_resolv_conf,
                         '/etc/netns/vpn/resolv.conf')

    def test_explicit_resolver_is_read_only_and_required(self):
        value = config(QB_DNS_RESOLV_CONF='/etc/example/vpn-resolver.conf')
        unit = cli._qbittorrent_service_content(value)
        self.assertIn('BindReadOnlyPaths=/etc/example/vpn-resolver.conf:/etc/resolv.conf', unit)
        self.assertNotIn('BindReadOnlyPaths=-', unit)
        self.assertNotIn('UMask=0077', unit)

    def test_rejects_unsafe_systemd_path_values(self):
        for value in ['relative.conf', '-/etc/resolv.conf', '/etc/a:b', '/etc/%n',
                      '/etc/space name', '/etc/new\nline', '/etc/back\\slash',
                      '/etc/quote"name', "/etc/quote'name", '/etc/null\0name',
                      '/etc/control\x7fname']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                cli._qbittorrent_service_content(config(QB_DNS_RESOLV_CONF=value))

    def test_auto_rejects_path_traversal_or_unit_injection_in_namespace(self):
        for name in ['../other', '.', '..', 'bad/name', 'bad name', 'bad%n', 'bad\nname']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                cli._qbittorrent_service_content(config(QB_DNS_RESOLV_CONF='auto', NETNS_NAME=name))

    def test_config_validation_reports_binding_error_without_echoing_input(self):
        with tempfile.NamedTemporaryFile(mode='w') as handle:
            handle.write('VPN_PROVIDER=pia\nPIA_USER=test\nPIA_PASS=test\n'
                         'TORRENT_CLIENT=qbittorrent\nQB_DNS_RESOLV_CONF=/etc/%n\n')
            handle.flush()
            valid, issues = validate_config(handle.name)
        self.assertFalse(valid)
        self.assertTrue(any('QB_DNS_RESOLV_CONF' in issue for issue in issues))
        self.assertFalse(any('/etc/%n' in issue for issue in issues))

    @patch('mole_pkg.cli.subprocess.run')
    def test_setup_installs_binding_from_selected_config(self, _run):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'etc/systemd/system').mkdir(parents=True)
            value = config(QB_DNS_RESOLV_CONF='auto', NETNS_NAME='example-vpn')
            with patch('mole_pkg.cli.Config', return_value=value), patch(
                'mole_pkg.cli.Path', side_effect=lambda path: root / str(path).lstrip('/')
            ):
                self.assertTrue(cli._qbittorrent_setup_services(verbose=False))
            unit = (root / 'etc/systemd/system/qbittorrent-mole.service').read_text()
        self.assertIn('BindReadOnlyPaths=/etc/netns/example-vpn/resolv.conf:/etc/resolv.conf', unit)

    def test_invalid_binding_does_not_write_service_artifacts(self):
        with patch('mole_pkg.cli.Config', return_value=config(QB_DNS_RESOLV_CONF='/etc/%n')), patch(
            'mole_pkg.cli.Path'
        ) as path:
            self.assertFalse(cli._qbittorrent_setup_services(verbose=False))
        path.assert_not_called()

    def test_setup_command_propagates_service_generation_failure(self):
        value = config(QB_USER='test-user')
        with patch('mole_pkg.cli.os.geteuid', return_value=0), patch(
            'mole_pkg.cli.run_cmd'
        ) as run, patch('mole_pkg.cli.Config', return_value=value), patch(
            'mole_pkg.cli.Path'
        ) as path, patch('mole_pkg.cli._qbittorrent_setup_services', return_value=False), patch(
            'builtins.input', return_value='n'
        ) as prompt, patch('mole_pkg.cli.subprocess.run') as systemctl:
            run.return_value.returncode = 0
            path.return_value.exists.return_value = False
            self.assertEqual(cli._qbittorrent_setup(argparse.Namespace()), 1)
        prompt.assert_not_called()
        systemctl.assert_not_called()
