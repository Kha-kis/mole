import ast
import asyncio
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock, AsyncMock

from mole_pkg import network


class KillSwitchPolicy(unittest.TestCase):
    def test_rebuild_remains_fail_closed(self):
        with patch.object(network, 'run_in_netns') as run:
            network.setup_killswitch(SimpleNamespace(netns='synthetic'))
        calls = [call.args[0] for call in run.call_args_list]
        for chain in ('INPUT', 'OUTPUT'):
            policy = ['iptables', '-P', chain, 'DROP']
            self.assertIn(policy, calls)
            self.assertLess(calls.index(policy), calls.index(['iptables', '-F', chain]))
        for cmd in calls:
            if cmd[:3] == ['iptables', '-A', 'OUTPUT'] and cmd[-2:] == ['-j', 'ACCEPT']:
                self.assertIn('-o', cmd, cmd)
        self.assertIn(['iptables', '-A', 'OUTPUT', '-m', 'comment', '--comment',
                       'mole-killswitch', '-j', 'DROP'], calls)
        self.assertFalse(any('--ctdir' in cmd for cmd in calls))

    def test_policy_failure_aborts_before_flush(self):
        failure = subprocess.CalledProcessError(1, 'iptables')
        with patch.object(network, 'run_in_netns', side_effect=failure) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                network.setup_killswitch(SimpleNamespace(netns='synthetic'))
        run.assert_called_once_with(['iptables', '-P', 'OUTPUT', 'DROP'], 'synthetic')

    def test_endpoint_rotation_removes_previous_exception(self):
        with patch.object(network, 'run_in_netns', return_value=SimpleNamespace(returncode=1)) as run:
            network.allow_vpn_server_ip(SimpleNamespace(netns='synthetic'),
                                        '198.51.100.2', '198.51.100.1')
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(calls[0], ['iptables', '-D', 'OUTPUT', '-o', 'veth-vpn',
                                    '-d', '198.51.100.1', '-j', 'ACCEPT'])
        self.assertEqual(calls[-1], ['iptables', '-I', 'OUTPUT', '3', '-o', 'veth-vpn',
                                     '-d', '198.51.100.2', '-j', 'ACCEPT'])

    def legacy_method(self, name, run):
        tree = ast.parse((Path(__file__).resolve().parents[1] / 'mole').read_text())
        method = next(node for cls in tree.body if isinstance(cls, ast.ClassDef)
                      for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and node.name == name)
        scope = {'run_in_netns': run, 'log': Mock(), 'Optional': __import__('typing').Optional,
                 'asyncio': SimpleNamespace(sleep=AsyncMock()), 'sanitize_for_log': str}
        exec(compile(ast.Module(body=[method], type_ignores=[]), '<legacy>', 'exec'), scope)
        return scope[name]

    def test_legacy_setup_has_the_same_strict_boundary(self):
        run = Mock(return_value=SimpleNamespace(returncode=0))
        method = self.legacy_method('_setup_killswitch', run)
        with patch.object(network, 'run_in_netns', run):
            method(SimpleNamespace(config=SimpleNamespace(netns='synthetic')))
        calls = [call.args[0] for call in run.call_args_list]
        self.assertIn(['iptables', '-P', 'OUTPUT', 'DROP'], calls)
        for cmd in calls:
            if cmd[:3] == ['iptables', '-A', 'OUTPUT'] and cmd[-2:] == ['-j', 'ACCEPT']:
                self.assertIn('-o', cmd)
                if 'veth-vpn' in cmd:
                    self.assertIn('-d', cmd)

    def test_legacy_connect_reconciles_endpoint_allowance(self):
        run = Mock(return_value=SimpleNamespace(returncode=0))
        method = self.legacy_method('_connect_vpn', run)
        config = SimpleNamespace(netns='synthetic', veth_host_ip='10.200.200.1', wg_conf='/synthetic')
        state = SimpleNamespace(server_ip='198.51.100.2', server_vip='10.0.0.1', connected=False)
        with patch.object(network, 'allow_vpn_server_ip') as allow:
            self.assertTrue(asyncio.run(method(SimpleNamespace(config=config, state=state), '198.51.100.1')))
            allow.assert_called_once_with(config, state.server_ip, '198.51.100.1')
