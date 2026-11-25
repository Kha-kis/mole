import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from mole_pkg.config import Config
from mole_pkg.providers.proton import ProtonProvider
from mole_pkg.utils import VPNState
from mole_pkg.recovery import ApprovedServerPolicy


def server(name, address):
    return dict(name=name, entry_ip=address, hostname='vpn.example.org', country='XX',
                public_key='synthetic-public-key', load=0)


class ApprovedPolicy(unittest.TestCase):
    def policy(self, names, initial='', cooldown=900):
        return ApprovedServerPolicy(names, initial, cooldown)

    def test_earliest_cooldown_is_destination_keyed_across_alias_and_key_change(self):
        policy = ApprovedServerPolicy(['NL#1', 'NL#2'])
        servers = [dict(name='NL#1', entry_ip='8.8.8.8'), dict(name='NL#2', entry_ip='1.1.1.1')]
        self.assertEqual(policy.next_eligible_at(servers, 100), 100)
        policy.failed('8.8.8.8', 100)
        policy.failed('1.1.1.1', 110)
        self.assertEqual(policy.next_eligible_at(servers, 120), 1000)
        alias = [dict(name='NL#2', entry_ip='8.8.8.8', public_key='changed')]
        self.assertEqual(policy.next_eligible_at(alias, 120), 1000)
        self.assertEqual(policy.next_eligible_at(alias, 1001), 1001)
        self.assertIsNone(policy.next_eligible_at([], 100))

    def test_ordering_wrap_and_physical_cooldown(self):
        policy = self.policy(['XX#1', 'XX#2', 'XX#3'], 'XX#2')
        servers = [server('XX#1', '192.0.2.1'), server('XX#2', '192.0.2.2'), server('XX#3', '192.0.2.2')]
        self.assertEqual([s['name'] for s in policy.candidates(servers, 0)], ['XX#2', 'XX#1'])
        policy.failed('192.0.2.2', 1)
        self.assertEqual([s['name'] for s in policy.candidates(servers, 2)], ['XX#1'])
        self.assertEqual(len(policy.candidates(servers, 902)), 2)

    def test_fresh_address_for_failed_logical_name_is_eligible(self):
        policy = self.policy(['XX#1'])
        policy.failed('192.0.2.1', 0)
        self.assertEqual(policy.candidates([server('XX#1', '192.0.2.1')], 1), [])
        self.assertEqual(len(policy.candidates([server('XX#1', '192.0.2.2')], 1)), 1)
        self.assertEqual(policy.candidates([server('YY#1', '192.0.2.3')], 1), [])

    def test_outside_pin_and_empty_list_are_invalid(self):
        for names, pin in [([], ''), (['XX#1'], 'YY#1'), (['XX#1', 'XX#1'], '')]:
            with self.subTest(names=names, pin=pin), self.assertRaises(ValueError):
                self.policy(names, pin)

    def test_configuration_is_opt_in_and_bounded(self):
        config = Config('/nonexistent')
        self.assertFalse(config.proton_failover_enabled)
        config._data.update(PROTON_FAILOVER_ENABLED='true', PROTON_FAILOVER_SERVERS='XX#1,XX#2', PROTON_SERVER='XX#1')
        self.assertEqual(config.proton_failover_servers, ['XX#1', 'XX#2'])
        self.assertEqual(config.proton_failover_max_attempts, 3)
        for key, value in [('PROTON_FAILOVER_SERVERS', ''), ('PROTON_FAILOVER_SERVERS', 'bad/server'),
                           ('PROTON_SERVER', 'YY#1'), ('PROTON_FAILOVER_MAX_ATTEMPTS', '4'),
                           ('PROTON_FAILOVER_COOLDOWN', '0')]:
            previous = config._data.get(key)
            config._data[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                config.validate_proton_failover()
            if previous is None:
                config._data.pop(key)
            else:
                config._data[key] = previous


class ProviderPolicy(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.config = Config('/nonexistent')
        self.config._data.update(STATE_DIR=self.root.name, PROTON_FAILOVER_ENABLED='true',
                                 PROTON_FAILOVER_SERVERS='XX#1,XX#2', PROTON_SERVER='XX#1')
        self.provider = ProtonProvider(self.config, VPNState())
        self.servers = [server('XX#1', '192.0.2.1'), server('XX#2', '192.0.2.2'), server('YY#1', '192.0.2.3')]

    async def test_failed_pin_moves_to_second_approved_endpoint(self):
        with patch.object(self.provider, '_fetch_servers', return_value=self.servers), patch.object(
            self.provider, '_filter_servers', side_effect=lambda values, country=None: values
        ):
            self.assertTrue(await self.provider.get_server())
            self.assertEqual(self.provider.state.server_ip, '192.0.2.1')
            if hasattr(self.provider, 'record_server_failure'):
                self.provider.record_server_failure('readiness')
            self.assertTrue(await self.provider.get_server())
            self.assertEqual(self.provider.state.server_ip, '192.0.2.2')

    async def test_saved_manual_and_country_controls_cannot_escape_list(self):
        self.servers[-1]['load'] = -1
        self.config._data.pop('PROTON_SERVER')
        self.config._data['PROTON_COUNTRY'] = 'YY'
        (Path(self.root.name) / 'server_name').write_text('YY#1')
        (Path(self.root.name) / 'new-server').touch()
        with patch.object(self.provider, '_fetch_servers', return_value=self.servers), patch.object(
            self.provider, '_filter_servers', side_effect=lambda values, country=None: values
        ):
            self.assertTrue(await self.provider.get_server())
        self.assertEqual(self.provider.state.server_ip, '192.0.2.1')

    async def test_disabled_failover_keeps_pin(self):
        self.config._data['PROTON_FAILOVER_ENABLED'] = 'false'
        with patch.object(self.provider, '_fetch_servers', return_value=self.servers), patch.object(
            self.provider, '_filter_servers', side_effect=lambda values, country=None: values
        ):
            self.assertTrue(await self.provider.get_server())
            if hasattr(self.provider, 'record_server_failure'):
                self.provider.record_server_failure('readiness')
            self.assertTrue(await self.provider.get_server())
        self.assertEqual(self.provider.state.server_ip, '192.0.2.1')

    async def test_unavailable_strict_pin_cannot_silently_choose_another_server(self):
        self.config._data['PROTON_FAILOVER_ENABLED'] = 'false'
        with patch.object(self.provider, '_fetch_servers', return_value=self.servers[1:]), patch.object(
            self.provider, '_filter_servers', side_effect=lambda values, country=None: values
        ):
            self.assertFalse(await self.provider.get_server())

    def test_disabled_physical_server_is_not_eligible(self):
        raw = dict(Name='XX#1', Status=1, Tier=2, Features=4, ExitCountry='XX',
                   Servers=[dict(Status=0, EntryIP='192.0.2.1', X25519PublicKey='synthetic')])
        self.assertEqual(self.provider._filter_servers([raw]), [])

    async def test_raw_provider_resolution_skips_shared_failure_and_accepts_address_churn(self):
        self.config._data['PROTON_FAILOVER_SERVERS'] = 'XX#1,XX#2,XX#3'

        def raw(name, address):
            return dict(Name=name, Domain='vpn.example.org', Status=1, Tier=2, Features=4, ExitCountry='XX',
                        Servers=[dict(Status=1, EntryIP=address, ExitIP=address, X25519PublicKey='synthetic')])

        values = [raw('XX#1', '192.0.2.1'), raw('XX#2', '192.0.2.1'), raw('XX#3', '192.0.2.2')]
        with patch.object(self.provider, '_fetch_servers', return_value=values):
            self.assertTrue(await self.provider.get_server())
            self.provider.record_server_failure('readiness')
            self.assertTrue(await self.provider.get_server())
            self.assertEqual(self.provider.state.server_ip, '192.0.2.2')
            self.provider.record_server_failure('readiness')
            values[0]['Servers'][0]['EntryIP'] = '192.0.2.3'
            self.assertTrue(await self.provider.get_server())
            self.assertEqual(self.provider.state.server_ip, '192.0.2.3')
