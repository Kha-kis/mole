import asyncio
import subprocess
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, PropertyMock, patch

from mole_pkg.providers.pia import PIAProvider
from mole_pkg.utils import read_runtime_readiness
import test_recovery_orchestration as fixtures


class IndependentLeaseRenewal(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        fixtures.RecoveryOrchestration.setUp(self)
        self.config._data['PORT_FORWARD'] = 'true'
        self.mole.provider._select(self.servers[0])
        state = self.mole.state
        state.server_ip = '192.0.2.1'
        self.mole._installed_peer_key = 'synthetic-peer'
        self.mole._installed_server_ip = '192.0.2.1'
        self.mole._installed_generation = state.generation
        self.mole._connecting = False
        state.port = 23456
        state.port_deadline = time.monotonic() + 60
        state.connected = state.tunnel_ready = state.forwarding_ready = True

    async def observe_keeper(self, replies, duration=.06):
        async def command(cmd, netns, timeout):
            self.assertEqual(cmd[:2], ['natpmpc', '-a'])
            self.assertEqual(netns, self.config.netns)
            self.assertEqual(timeout, 10)
            protocol = cmd[4].upper()
            replies.append(protocol)
            return subprocess.CompletedProcess(
                cmd, 0, 'Mapped public port 23456 protocol ' + protocol
                + ' to local port 1 lifetime 60\n', '')

        with patch.object(type(self.config), 'keepalive_interval',
                          new_callable=PropertyMock, return_value=.01), patch(
                'mole_pkg.providers.proton.async_run_in_netns', side_effect=command):
            task = asyncio.create_task(self.mole._keepalive_loop())
            try:
                await asyncio.sleep(duration)
            finally:
                self.mole.shutdown_event.set()
                await asyncio.wait_for(task, .2)

    async def test_failed_health_probe_does_not_starve_installed_lease(self):
        # Keeping the old connected-only gate must make this regression fail.
        self.mole.torrent = Mock(set_interface=AsyncMock(return_value=True),
                                 set_listen_port=AsyncMock(return_value=True))
        with patch.object(self.mole, '_verify_transport', new=AsyncMock(return_value=False)):
            self.assertFalse(await self.mole._check_health())
        before = self.mole.state.port_deadline
        replies = []
        await self.observe_keeper(replies)
        self.assertIn('UDP', replies)
        self.assertIn('TCP', replies)
        self.assertGreater(self.mole.state.port_deadline, before)
        self.assertEqual(self.mole.state.last_error, 'health_unproven')
        self.assertFalse(self.mole.state.client_ready)
        evidence = read_runtime_readiness(Path(self.root.name))
        self.assertFalse(evidence['connected'])
        self.assertFalse(evidence['forwarding_ready'])
        self.assertFalse(evidence['client_ready'])

    async def test_no_installed_peer_does_not_renew_saved_port(self):
        self.mole._installed_peer_key = None
        await self.assert_no_renewal()

    async def test_missing_installed_address_does_not_renew(self):
        self.mole._installed_server_ip = self.mole.state.server_ip = None
        await self.assert_no_renewal()

    async def test_failed_mapping_then_recovery_preserves_transport_error(self):
        with patch.object(self.mole, '_verify_transport', new=AsyncMock(return_value=False)):
            self.assertFalse(await self.mole._check_health())
        self.mole._mapping_result(False)
        replies = []
        await self.observe_keeper(replies)
        self.assertIn('TCP', replies)
        self.assertEqual(self.mole.state.last_error, 'health_unproven')
        self.assertFalse(self.mole.state.connected)

    async def test_pia_disconnected_state_does_not_maintain_lease(self):
        self.mole.provider = PIAProvider(self.config, self.mole.state)
        self.mole.state.connected = False
        await self.observe_pia_lease()
        self.assertFalse((Path(self.root.name) / 'last_port_forward_success_ts').exists())

    async def test_pia_connected_state_still_maintains_lease(self):
        self.mole.provider = PIAProvider(self.config, self.mole.state)
        await self.observe_pia_lease()
        self.assertTrue((Path(self.root.name) / 'last_port_forward_success_ts').exists())

    async def observe_pia_lease(self):
        with patch.object(self.mole.provider, 'refresh_port_forward',
                          new=AsyncMock(return_value=True)):
            await self.observe_keeper([])

    async def test_stale_generation_does_not_renew(self):
        self.mole._installed_generation = self.mole.state.generation - 1
        await self.assert_no_renewal()

    async def test_different_installed_address_does_not_renew(self):
        self.mole._installed_server_ip = '192.0.2.2'
        await self.assert_no_renewal()

    async def test_wireguard_replacement_does_not_renew(self):
        self.mole._connecting = True
        await self.assert_no_renewal()

    async def assert_no_renewal(self):
        replies = []
        before = self.mole.state.port_deadline
        await self.observe_keeper(replies)
        self.assertEqual(replies, [])
        self.assertEqual(self.mole.state.port_deadline, before)
