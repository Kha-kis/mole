import asyncio
import inspect
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

from mole_pkg import network
from mole_pkg.mole import Mole
import test_recovery_orchestration as fixtures


class BoundedLifecycle(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixtures.RecoveryOrchestration.setUp(self)

    async def test_hook_wait_keeps_heartbeat_and_hides_output(self):
        self.assertTrue(inspect.iscoroutinefunction(Mole._run_hook))
        hook = Path(self.root.name) / 'hook'
        hook.write_text('#!/bin/sh\nexit 1\n')
        hook.chmod(0o700)
        beats = []

        async def command(cmd, netns, timeout, env=None):
            self.assertEqual(timeout, 30)
            await asyncio.sleep(.1)
            return subprocess.CompletedProcess(cmd, 1, 'synthetic-secret', 'synthetic-secret')

        async def heartbeat():
            await asyncio.sleep(.01)
            beats.append(time.monotonic())

        start = time.monotonic()
        with patch('mole_pkg.mole.async_run_in_netns', side_effect=command), self.assertLogs('mole', 'WARNING') as logs:
            result, _ = await asyncio.gather(Mole._run_hook(self.mole, str(hook), 'HOOK'), heartbeat())
        self.assertFalse(result)
        self.assertLess(beats[0] - start, .08)
        self.assertNotIn('synthetic-secret', str(logs.output))

    async def test_service_restart_is_bounded_without_blocking(self):
        self.assertTrue(hasattr(__import__('mole_pkg.mole', fromlist=['async_run_command']), 'async_run_command'))
        beats = []

        async def command(cmd, timeout):
            self.assertEqual(cmd, ['systemctl', 'restart', 'qbittorrent-mole'])
            self.assertEqual(timeout, 10)
            await asyncio.sleep(.1)
            return subprocess.CompletedProcess(cmd, 1, '', 'synthetic-secret')

        async def heartbeat():
            await asyncio.sleep(.01)
            beats.append(time.monotonic())

        start = time.monotonic()
        with patch('mole_pkg.mole.async_run_command', side_effect=command), self.assertLogs('mole', 'ERROR') as logs:
            result, _ = await asyncio.gather(self.mole._restart_torrent_service(), heartbeat())
        self.assertFalse(result)
        self.assertLess(beats[0] - start, .08)
        self.assertNotIn('synthetic-secret', str(logs.output))

    async def test_setup_worker_has_outer_deadline_and_private_configuration(self):
        self.assertTrue(callable(getattr(network, 'async_setup_namespace', None)))
        seen = []

        async def command(cmd, timeout, **kwargs):
            seen.append(timeout)
            self.assertNotIn('PROTON_PASS', kwargs['input_data'].decode())
            await asyncio.sleep(.01)
            return subprocess.CompletedProcess(cmd, 0, '', '')

        with patch.object(network, 'async_run_command', side_effect=command):
            await network.async_setup_namespace(self.config)
        self.assertEqual(seen, [120])

    async def test_failed_endpoint_rule_prevents_success(self):
        self.assertTrue(callable(getattr(network, 'async_allow_vpn_server_ip', None)))
        with patch.object(network, 'async_run_in_netns', new=AsyncMock(
                return_value=subprocess.CompletedProcess([], 1, '', 'private'))):
            with self.assertRaises(RuntimeError):
                await network.async_allow_vpn_server_ip(self.config, '192.0.2.2', '192.0.2.1')

    async def test_candidate_preparation_preserves_installed_monitoring_and_lease(self):
        state = self.mole.state
        self.mole.provider._select(self.servers[0])
        state.connected = state.tunnel_ready = state.forwarding_ready = True
        state.port = 23456
        state.port_deadline = time.monotonic() + 60
        self.mole._installed_server_ip = state.server_ip
        self.mole._installed_peer_key = 'old-peer'
        self.mole._installed_generation = state.generation
        self.config._data.update(PORT_FORWARD='true', KEEPALIVE_INTERVAL='0.01')
        generation = state.generation
        self.mole.provider._select(self.servers[1])
        self.assertEqual(state.server_ip, '192.0.2.1')
        started, renewed = asyncio.Event(), asyncio.Event()

        async def register():
            started.set()
            await asyncio.Event().wait()

        async def refresh():
            renewed.set()
            return True

        self.mole.provider.register_wireguard = AsyncMock(side_effect=register)
        self.mole.provider.refresh_port_forward = AsyncMock(side_effect=refresh)
        task = asyncio.create_task(self.mole._attempt_selected_server('192.0.2.1'))
        interval = patch.object(type(self.config), 'keepalive_interval', new_callable=PropertyMock, return_value=.01)
        interval.start()
        keeper = asyncio.create_task(self.mole._keepalive_loop())
        try:
            await started.wait()
            with patch.object(self.mole, '_verify_transport', new=AsyncMock(return_value=True)):
                self.assertTrue(await self.mole._check_health())
            await asyncio.wait_for(renewed.wait(), .2)
            self.assertEqual(state.generation, generation)
            self.assertEqual(state.server_ip, '192.0.2.1')
            self.assertTrue(state.forwarding_ready)
        finally:
            task.cancel()
            keeper.cancel()
            await asyncio.gather(task, keeper, return_exceptions=True)
            interval.stop()

    async def test_actual_switch_advances_generation_once(self):
        self.mole.provider._select(self.servers[0])
        self.mole._connect_vpn = Mole._connect_vpn.__get__(self.mole)
        with patch('mole_pkg.mole.read_wg_peer_key', return_value='new-peer'), patch(
                'mole_pkg.mole.async_run_in_netns', new=AsyncMock(return_value=Mock(returncode=0))
        ), patch('mole_pkg.mole.async_allow_vpn_server_ip', new=AsyncMock()), patch.object(
                self.mole, '_wait_for_readiness', new=AsyncMock(return_value=True)):
            self.assertTrue(await self.mole._attempt_selected_server(None))
        self.assertEqual(self.mole.state.generation, 1)
        self.assertEqual(self.mole._installed_generation, 1)

    async def test_hook_timeout_is_not_tunnel_failure(self):
        hook = Path(self.root.name) / 'hook'
        hook.touch(mode=0o700)
        self.mole.state.connected = self.mole.state.tunnel_ready = True
        with patch('mole_pkg.mole.async_run_in_netns', new=AsyncMock(side_effect=asyncio.TimeoutError)):
            self.assertFalse(await Mole._run_hook(self.mole, str(hook), 'HOOK'))
        self.assertTrue(self.mole.state.connected)

    async def test_failed_endpoint_rule_never_brings_up_wireguard(self):
        self.mole.state.server_ip = '192.0.2.1'
        calls = []

        async def command(cmd, *args, **kwargs):
            calls.append(cmd)
            return Mock(returncode=0)

        with patch('mole_pkg.mole.read_wg_peer_key', return_value='new-peer'), patch(
                'mole_pkg.mole.async_run_in_netns', side_effect=command), patch(
                'mole_pkg.mole.async_allow_vpn_server_ip', new=AsyncMock(side_effect=RuntimeError)):
            self.assertFalse(await Mole._connect_vpn(self.mole, None))
        self.assertFalse(any(cmd[:2] == ['wg-quick', 'up'] for cmd in calls))
        self.assertFalse(self.mole.state.connected)


class NamespaceProtection(unittest.TestCase):
    def test_worker_does_not_ignore_mutating_command_failure(self):
        from mole_pkg.network_worker import bounded_command
        with self.assertRaises(subprocess.CalledProcessError):
            bounded_command([sys.executable, '-c', 'import sys; sys.exit(7)'], check=False)

    def test_drop_precedes_external_link_and_nat(self):
        events = []
        config = Mock(netns='synthetic', veth_host_ip='10.200.200.1',
                      veth_vpn_ip='10.200.200.2', host_interface='synthetic')

        def command(cmd, *args, **kwargs):
            events.append(cmd)
            return subprocess.CompletedProcess(cmd, 1 if cmd[:3] == ['ip', 'link', 'show'] else 0, '', '')

        with patch.object(network, 'run_cmd', side_effect=command), patch.object(
                network, 'run_in_netns', side_effect=command), patch.object(Path, 'write_text'):
            network.setup_namespace(config)
        drop = events.index(['iptables', '-P', 'OUTPUT', 'DROP'])
        enabled = [i for i, cmd in enumerate(events) if cmd[-1:] == ['up'] or 'MASQUERADE' in cmd]
        self.assertTrue(enabled)
        self.assertTrue(all(drop < i for i in enabled))

    def test_failed_policy_never_enables_external_path(self):
        events = []
        config = Mock(netns='synthetic', veth_host_ip='10.200.200.1',
                      veth_vpn_ip='10.200.200.2', host_interface='synthetic')

        def command(cmd, *args, **kwargs):
            events.append(cmd)
            if cmd == ['iptables', '-P', 'OUTPUT', 'DROP']:
                raise subprocess.CalledProcessError(1, cmd)
            return subprocess.CompletedProcess(cmd, 1, '', '')

        with patch.object(network, 'run_cmd', side_effect=command), patch.object(
                network, 'run_in_netns', side_effect=command), patch.object(Path, 'write_text'):
            with self.assertRaises(subprocess.CalledProcessError):
                network.setup_namespace(config)
        self.assertFalse(any(cmd[-1:] == ['up'] or 'MASQUERADE' in cmd for cmd in events))
