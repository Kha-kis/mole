"""Canonical, policy-filtered Proton discovery and private durable records."""

import base64
import binascii
import ipaddress
import contextlib
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time


NAME = re.compile(r'[A-Z]{2}(?:-[A-Z0-9]+)*#[0-9]+\Z', re.ASCII)
HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)


def public_ipv4(value):
    if not isinstance(value, str):
        raise ValueError('invalid public IPv4')
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global or str(address) != value:
        raise ValueError('invalid public IPv4')
    return value


def _hostname(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 253 or
            not value.isascii() or any(not re.fullmatch(
                r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label, re.ASCII)
                for label in value.split('.'))):
        raise ValueError('invalid discovery hostname')
    return value.lower()


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('invalid discovery integer')
    return value


def canonical_candidate(record):
    """Validate a persisted or freshly normalized candidate without coercion."""
    if not isinstance(record, dict):
        raise ValueError('invalid candidate')
    name = record.get('name')
    if not isinstance(name, str) or len(name) > 64 or not NAME.fullmatch(name):
        raise ValueError('invalid candidate name')
    key = record.get('public_key')
    try:
        decoded = base64.b64decode(key, validate=True)
        if len(decoded) != 32 or base64.b64encode(decoded).decode('ascii') != key:
            raise ValueError
    except (ValueError, TypeError, binascii.Error):
        raise ValueError('invalid candidate public key') from None
    country = record.get('country')
    if not isinstance(country, str) or not re.fullmatch(r'[A-Z]{2}', country, re.ASCII):
        raise ValueError('invalid candidate country')
    load = record.get('load')
    if type(load) not in (int, float) or not math.isfinite(load) or not 0 <= load <= 100:
        raise ValueError('invalid candidate load')
    return dict(name=name, hostname=_hostname(record.get('hostname')),
                entry_ip=public_ipv4(record.get('entry_ip')),
                exit_ip=public_ipv4(record['exit_ip']) if record.get('exit_ip') is not None else None,
                public_key=key, port=_integer(record.get('port'), 51820, 51820),
                tier=_integer(record.get('tier'), 0, 2),
                features=_integer(record.get('features'), 0, 2**63 - 1),
                load=load, country=country)


def normalize_candidates(logicals, approved_names, tier, require_p2p):
    """Keep all eligible physical destinations; never guess conflicting keys."""
    _integer(tier, 0, 2)
    if (not isinstance(logicals, list) or not logicals or
            any(not isinstance(item, dict) or not isinstance(item.get('Servers'), list)
                for item in logicals)):
        raise ValueError('invalid global discovery catalogue')
    if (not isinstance(approved_names, list) or not approved_names or
            len(approved_names) > 32 or len(set(approved_names)) != len(approved_names) or
            any(not isinstance(n, str) or len(n) > 64 or not NAME.fullmatch(n) for n in approved_names)):
        raise ValueError('invalid approved names')
    eligible, keys = [], {}
    for logical in logicals:
        for physical in logical['Servers']:
            if not isinstance(physical, dict):
                raise ValueError('invalid global physical catalogue')
            try:
                candidate = canonical_candidate(dict(
                    name=logical.get('Name'), hostname=physical.get('Domain') or logical.get('Domain'),
                    entry_ip=physical.get('EntryIP'), exit_ip=physical.get('ExitIP'),
                    public_key=physical.get('X25519PublicKey'), port=51820,
                    tier=logical.get('Tier'), features=logical.get('Features'),
                    load=logical.get('Load'), country=logical.get('ExitCountry')))
            except ValueError:
                continue
            keys.setdefault(candidate['entry_ip'], set()).add(candidate['public_key'])
            if (logical.get('Status') != 1 or physical.get('Status') != 1 or
                    candidate['name'] not in approved_names or candidate['tier'] > tier or
                    (require_p2p and not candidate['features'] & 4)):
                continue
            eligible.append(candidate)
    eligible.sort(key=lambda c: (approved_names.index(c['name']), c['entry_ip'], c['public_key']))
    result, seen = [], set()
    for candidate in eligible:
        address = candidate['entry_ip']
        if address not in seen and len(keys[address]) == 1:
            seen.add(address)
            result.append(candidate)
    return result


def identity_scope(origin, uid, account, tier, certificate_public):
    if (not all(isinstance(x, str) and x for x in (origin, uid, account, certificate_public)) or
            type(tier) is not int or not 0 <= tier <= 2):
        raise ValueError('incomplete discovery binding')
    digest = lambda value: hashlib.sha256(value.encode()).hexdigest()
    value = [origin, uid, digest(account), tier, digest(certificate_public)]
    return digest(json.dumps(value, separators=(',', ':')))


def _timestamp(value, minimum=0):
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum:
        raise ValueError('invalid discovery timestamp')
    return value


def _record(value):
    if not isinstance(value, dict) or type(value.get('schema')) is not int or value['schema'] != 1:
        raise ValueError('unknown discovery schema')
    if not isinstance(value.get('scope'), str) or not HEX.fullmatch(value['scope']):
        raise ValueError('invalid discovery scope')
    tier = _integer(value.get('entitlement_tier'), 0, 2)
    _timestamp(value.get('entitlement_observed_wall'), 1)
    _timestamp(value.get('observed_wall'), 1)
    _timestamp(value.get('observed_mono'))
    boot = value.get('boot_id')
    if not isinstance(boot, str) or not 1 <= len(boot) <= 128 or not boot.isascii() or any(ord(c) < 33 for c in boot):
        raise ValueError('invalid discovery boot')
    candidates = value.get('candidates')
    if not isinstance(candidates, list) or len(candidates) > 512:
        raise ValueError('invalid discovery pool')
    normalized = [canonical_candidate(c) for c in candidates]
    if (any(c['tier'] > tier for c in normalized) or
            len({c['entry_ip'] for c in normalized}) != len(normalized)):
        raise ValueError('conflicting discovery pool')
    return dict(value, candidates=normalized)


class _PrivateRecord:
    LIMIT = 4 * 1024 * 1024

    def __init__(self, path):
        self.path = Path(path)

    @contextlib.contextmanager
    def _directory(self):
        parent = self.path.parent
        if not self.path.is_absolute() or '..' in self.path.parts or parent.resolve() != parent:
            raise ValueError('unsafe private record path')
        for ancestor in [parent, *parent.parents]:
            info = ancestor.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or
                    info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022):
                raise ValueError('unsafe private record parent')
        info = parent.stat()
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('private record directory requires mode 0700 and service ownership')
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            yield fd
        finally:
            os.close(fd)

    def _read(self):
        with self._directory() as directory:
            try:
                fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                return None
            with os.fdopen(fd, 'rb') as handle:
                info = os.fstat(handle.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                        stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > self.LIMIT):
                    raise ValueError('unsafe private record')
                data = handle.read(self.LIMIT + 1)
                if len(data) > self.LIMIT:
                    raise ValueError('oversized private record')
                return json.loads(data)

    def _write(self, record):
        encoded = json.dumps(record, allow_nan=False, separators=(',', ':')).encode()
        if len(encoded) > self.LIMIT:
            raise ValueError('oversized private record')
        with self._directory() as directory:
            try:
                old = os.stat(self.path.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if (not stat.S_ISREG(old.st_mode) or old.st_uid != os.geteuid() or
                        stat.S_IMODE(old.st_mode) != 0o600):
                    raise ValueError('unsafe private record replacement')
            name = '.' + self.path.name + '-' + secrets.token_hex(16)
            fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                with os.fdopen(fd, 'wb') as handle:
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(name, self.path.name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                try:
                    os.unlink(name, dir_fd=directory)
                except FileNotFoundError:
                    pass

    def _delete(self):
        with self._directory() as directory:
            os.unlink(self.path.name, dir_fd=directory)
            os.fsync(directory)


class DiscoveryCache(_PrivateRecord):
    def publish(self, record):
        self._write(_record(record))

    def load(self, scope, now_wall, now_mono, boot_id, max_age):
        try:
            _integer(max_age, 0, 86400)
            if not max_age:
                return None
            value = _record(self._read())
            if value['scope'] != scope:
                return None
            ages = [now_wall - value['observed_wall'], now_wall - value['entitlement_observed_wall']]
            if value['boot_id'] == boot_id:
                ages.append(now_mono - value['observed_mono'])
            if any(not math.isfinite(age) or not 0 <= age <= max_age for age in ages):
                return None
            return dict(value, cache_age_seconds=max(ages))
        except (OSError, ValueError, TypeError, KeyError):
            return None


class RejectionJournal(_PrivateRecord):
    """Durable pre-operation pending barrier; no rejection expires into trust."""
    @contextlib.contextmanager
    def _lock(self):
        with self._directory() as directory:
            fd = os.open(self.path.name + '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                        stat.S_IMODE(info.st_mode) != 0o600):
                    raise ValueError('unsafe rejection lock')
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)

    def _checked(self):
        value = self._read()
        if value is None:
            return None
        if (not isinstance(value, dict) or not HEX.fullmatch(value.get('scope', '')) or
                not HEX.fullmatch(value.get('transaction_id', '')) or
                value.get('kind') not in ('pending', 'credentials_rejected', 'compatibility', 'certificate_rejected')):
            raise ValueError('invalid rejection barrier')
        _timestamp(value.get('observed_wall'), 1)
        return value

    def blocked(self, scope):
        try:
            return self._checked() is not None
        except (OSError, ValueError, TypeError):
            return True

    def begin(self, scope, now_wall):
        if not isinstance(scope, str) or not HEX.fullmatch(scope):
            raise ValueError('invalid rejection scope')
        _timestamp(now_wall, 1)
        with self._lock():
            previous = self._checked()
            if previous is not None:
                return previous['transaction_id'], False
            transaction = secrets.token_hex(32)
            self._write(dict(scope=scope, transaction_id=transaction, kind='pending', observed_wall=now_wall))
            return transaction, True

    def finish(self, scope, transaction, outcome, created, *, revalidated=False):
        with self._lock():
            current = self._checked()
            if current is None or current['transaction_id'] != transaction:
                return False
            if outcome in ('credentials_rejected', 'compatibility', 'certificate_rejected'):
                self._write(dict(scope=scope, transaction_id=secrets.token_hex(32),
                                 kind=outcome, observed_wall=time.time()))
            elif ((outcome == 'transient' and created and current['scope'] == scope and
                   current['kind'] == 'pending') or (outcome == 'success' and revalidated)):
                self._delete()
            return True
