import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from mole_pkg.discovery import normalize_candidates


KEY = base64.b64encode(bytes(range(32))).decode()
OTHER_KEY = base64.b64encode(bytes(range(1, 33))).decode()


def logical(name='NL#1'):
    return dict(Name=name, Domain='logical.example.com', Status=1, Tier=2,
                ExitCountry='NL', Features=4, Load=20, Servers=[
                    dict(Domain='physical.example.com', Status=1, EntryIP='8.8.8.8',
                         ExitIP='9.9.9.9', X25519PublicKey=KEY),
                    dict(Status=1, EntryIP='1.1.1.1', ExitIP=None, X25519PublicKey=KEY)])


class NormalizeCandidates(unittest.TestCase):
    def test_keeps_every_physical_entry_in_stable_priority_order(self):
        second = logical('NL#2')
        second['Servers'] = [dict(second['Servers'][0], EntryIP='4.2.2.2')]
        result = normalize_candidates([second, logical()], ['NL#1', 'NL#2'], 2, True)
        self.assertEqual([s['entry_ip'] for s in result], ['1.1.1.1', '8.8.8.8', '4.2.2.2'])
        self.assertEqual(result[0]['hostname'], 'logical.example.com')
        self.assertEqual(result[1]['hostname'], 'physical.example.com')
        self.assertEqual(result[1]['port'], 51820)

    def test_filters_disabled_tier_p2p_and_unapproved(self):
        for field, value in [('Status', 0), ('Tier', 3), ('Features', 0),
                             ('Load', float('nan')), ('ExitCountry', 'nl')]:
            item = logical()
            item[field] = value
            self.assertEqual(normalize_candidates([item], ['NL#1'], 2, True), [])
        self.assertEqual(normalize_candidates([logical()], ['NL#2'], 2, True), [])
        self.assertEqual(normalize_candidates([logical()], ['NL#1'], 1, True), [])
        item = logical()
        item['Servers'][0]['Status'] = 0
        self.assertEqual(len(normalize_candidates([item], ['NL#1'], 2, True)), 1)

    def test_rejects_invalid_address_key_and_hostname(self):
        for field, value in [('EntryIP', '192.168.1.1'), ('EntryIP', '2001:4860::8888'),
                             ('ExitIP', '127.0.0.1'), ('X25519PublicKey', 'bad'),
                             ('Domain', 'https://user:pass@host'), ('Domain', 'bad host')]:
            item = logical()
            item['Servers'] = [dict(item['Servers'][0], **{field: value})]
            self.assertEqual(normalize_candidates([item], ['NL#1'], 2, True), [])

    def test_alias_dedup_and_conflicting_keys_remove_destination(self):
        alias = logical('NL#2')
        result = normalize_candidates([alias, logical()], ['NL#1', 'NL#2'], 2, True)
        self.assertEqual([s['name'] for s in result], ['NL#1', 'NL#1'])
        alias['Servers'][0]['X25519PublicKey'] = OTHER_KEY
        result = normalize_candidates([alias, logical()], ['NL#1', 'NL#2'], 2, True)
        self.assertEqual([s['entry_ip'] for s in result], ['1.1.1.1'])

    def test_malformed_catalogue_is_not_a_valid_withdrawal(self):
        for data in ([], {}, [None], [dict(logical(), Servers='invalid')]):
            with self.assertRaises(ValueError):
                normalize_candidates(data, ['NL#1'], 2, True)
        self.assertEqual(normalize_candidates([logical('NL#2')], ['NL#1'], 2, True), [])


class DiscoveryPersistence(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def record(self):
        return dict(schema=1, scope='a' * 64, entitlement_tier=2,
                    entitlement_observed_wall=990, observed_wall=1000,
                    boot_id='boot', observed_mono=100,
                    candidates=normalize_candidates([logical()], ['NL#1'], 2, True))

    def test_cache_keeps_original_age_and_expires_on_greater_clock(self):
        from mole_pkg.discovery import DiscoveryCache
        cache = DiscoveryCache(self.root / 'cache.json')
        cache.publish(self.record())
        self.assertEqual(cache.load('a' * 64, 1010, 110, 'boot', 100)['observed_wall'], 1000)
        self.assertIsNone(cache.load('a' * 64, 1010, 250, 'boot', 100))
        self.assertIsNone(cache.load('a' * 64, 1001, 101, 'boot', 0))
        self.assertIsNone(cache.load('a' * 64, 999, 110, 'new-boot', 100))
        self.assertIsNone(cache.load('a' * 64, 1100, 110, 'boot', 100))  # older entitlement
        self.assertIsNone(cache.load('b' * 64, 1010, 110, 'boot', 100))

    def test_invalid_publish_preserves_old_and_unsafe_file_is_rejected(self):
        from mole_pkg.discovery import DiscoveryCache
        path = self.root / 'cache.json'
        cache = DiscoveryCache(path)
        cache.publish(self.record())
        original = path.read_bytes()
        for change in ({'schema': True}, {'observed_wall': float('nan')},
                       {'candidates': [None]}, {'entitlement_tier': 3}):
            with self.assertRaises(ValueError):
                cache.publish(dict(self.record(), **change))
            self.assertEqual(path.read_bytes(), original)
        path.chmod(0o644)
        self.assertIsNone(cache.load('a' * 64, 1010, 110, 'boot', 100))
        path.unlink()
        target = self.root / 'target'
        target.write_bytes(original)
        target.chmod(0o600)
        path.symlink_to(target)
        self.assertIsNone(cache.load('a' * 64, 1010, 110, 'boot', 100))
        with self.assertRaises((ValueError, OSError)):
            cache.publish(self.record())

    def test_valid_withdrawal_empty_pool_replaces_old_candidates(self):
        from mole_pkg.discovery import DiscoveryCache
        cache = DiscoveryCache(self.root / 'cache.json')
        cache.publish(self.record())
        cache.publish(dict(self.record(), candidates=[]))
        self.assertEqual(cache.load('a' * 64, 1010, 110, 'boot', 100)['candidates'], [])

    def test_rejection_survives_timeout_restart_and_stale_transaction(self):
        from mole_pkg.discovery import RejectionJournal
        path = self.root / 'blocked.json'
        journal = RejectionJournal(path)
        tx, created = journal.begin('a' * 64, 1000)
        self.assertTrue(created)
        self.assertTrue(RejectionJournal(path).blocked('a' * 64))
        journal.finish('a' * 64, tx, 'credentials_rejected', created)
        tx2, created2 = journal.begin('a' * 64, 1010)
        self.assertFalse(created2)
        journal.finish('a' * 64, tx2, 'transient', created2)
        self.assertTrue(journal.blocked('a' * 64))
        journal.finish('a' * 64, tx, 'success', True, revalidated=True)
        self.assertTrue(journal.blocked('a' * 64))  # stale pre-rejection identity
        journal.finish('a' * 64, tx2, 'success', created2, revalidated=True)
        self.assertFalse(journal.blocked('a' * 64))
