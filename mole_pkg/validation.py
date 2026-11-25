"""Immutable connection identities and bounded authorization evidence."""

import math
import hashlib
import asyncio
import contextlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .discovery import HEX, canonical_candidate, public_ipv4


class AuthorizationDenied(ValueError):
    """A well-formed, identity-bound explicit policy denial."""


def configuration_digest(config):
    values = {key: config.get(key, '') for key in (
        'VPN_PROVIDER', 'PROTON_FAILOVER_SERVERS', 'PROTON_SERVER', 'PROTON_TIER',
        'PROTON_PREFER_P2P', 'PORT_FORWARD', 'NETNS_NAME', 'PROTON_RECOVERY_MODE')}
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def trusted_executable(path):
    value = Path(path)
    if not value.is_absolute() or '..' in value.parts:
        raise ValueError('validator must be absolute')
    for component in [*reversed(value.parents), value]:
        info = component.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError('validator path is not trusted')
    info = value.lstat()
    if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
        raise ValueError('validator is not executable')
    return str(value)


def validate_cgroup_root(path):
    root, mount = Path(path), Path('/sys/fs/cgroup')
    if (not root.is_absolute() or root == mount or mount not in root.parents or
            root.resolve() != root or not (mount / 'cgroup.controllers').is_file() or
            not (root / 'cgroup.procs').is_file()):
        raise RuntimeError('delegated cgroup v2 root unavailable')
    for component in [root, *list(root.parents)[:len(root.relative_to(mount).parts)]]:
        info = component.lstat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise RuntimeError('unsafe cgroup root')
    return root


async def _drain(task):
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
    return task.result()


@contextlib.asynccontextmanager
async def owned_child(command):
    spawn = asyncio.create_task(asyncio.create_subprocess_exec(
        *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL, start_new_session=True, limit=65537,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
             'PYTHONPATH': str(Path(__file__).resolve().parents[1]),
             'PYTHONDONTWRITEBYTECODE': '1'}))
    process = None
    try:
        process = await asyncio.shield(spawn)
        yield process
    finally:
        if process is None:
            process = await _drain(spawn)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await _drain(asyncio.create_task(process.wait()))


async def _json_line(process):
    if process.stdout is None:
        raise ValueError('helper output pipe unavailable')
    line = await process.stdout.readline()
    if not line or len(line) > 65536:
        raise ValueError('invalid helper reply')
    reply = json.loads(line)
    if not isinstance(reply, dict):
        raise ValueError('invalid helper reply')
    return reply


async def bounded_json_command(command, request, timeout):
    encoded = json.dumps(request, allow_nan=False).encode() + b'\n'
    if len(encoded) > 65536 or timeout <= 0:
        raise RuntimeError('validation helper unavailable')

    async def execute():
        async with owned_child(command) as process:
            if process.stdin is None or process.stdout is None:
                raise RuntimeError('helper pipes unavailable')
            process.stdin.write(encoded)
            await process.stdin.drain()
            process.stdin.close()
            result = await _json_line(process)
            # A second byte/line is not part of the bounded JSON contract.
            extra = await process.stdout.read(1)
            if extra or await process.wait() != 0:
                raise ValueError
            return result

    try:
        return await asyncio.wait_for(execute(), timeout)
    except (OSError, ValueError, TypeError, asyncio.TimeoutError):
        raise RuntimeError('validation helper unavailable') from None


class ExitValidator:
    """Only the observer's cgroup receives temporary namespace connectivity."""
    def __init__(self, config, gate, *, _observer_command=None, _resolve_targets=None):
        self.config, self.gate = config, gate
        # Constructor-only test seams; no config, environment or CLI can set them.
        self._observer_command = _observer_command
        self._resolve_targets = _resolve_targets

    async def describe(self, config_digest, deadline):
        executable = trusted_executable(self.config.get('PROTON_EXIT_VALIDATOR', ''))
        reply = await bounded_json_command([executable],
                    dict(operation='describe', config_digest=config_digest), deadline - time.monotonic())
        revision = reply.get('policy_revision')
        if not isinstance(revision, str) or not HEX.fullmatch(revision):
            raise ValueError('invalid validator policy revision')
        return revision

    def _create_cgroup(self, attempt, round_):
        root = validate_cgroup_root(self.config.get('PROTON_VALIDATION_CGROUP_ROOT', ''))
        group = root / ('mole-probe-' + round_.id[:24])
        group.mkdir(mode=0o700)
        return group

    async def observe(self, attempt, round_, deadline):
        if self._resolve_targets is None:
            targets_reply = await bounded_json_command(
                [sys.executable, '-m', 'mole_pkg.validation_worker', 'resolve'], {},
                min(3, deadline - time.monotonic()))
            targets = targets_reply.get('targets')
        else:
            targets = await self._resolve_targets(deadline)
        from .validation_worker import validate_targets
        targets = validate_targets(targets)
        group = self._create_cgroup(attempt, round_)
        try:
            command = self._observer_command or [sys.executable, '-m', 'mole_pkg.validation_worker']
            async with owned_child(['ip', 'netns', 'exec', self.config.netns] + list(command)) as process:
                ready = await asyncio.wait_for(_json_line(process), 2)
                if ready != {'ready': True, 'pid': process.pid}:
                    raise RuntimeError('observer barrier failed')
                (group / 'cgroup.procs').write_text(str(process.pid))
                expected = '0::/' + str(group.relative_to('/sys/fs/cgroup'))
                if Path('/proc/{}/cgroup'.format(process.pid)).read_text().strip() != expected:
                    raise RuntimeError('observer cgroup membership failed')
                await self.gate.prepare_probe(attempt, round_, group, targets)
                request = dict(targets=targets, nonce=attempt.nonce, round_id=round_.id)
                if process.stdin is None:
                    raise RuntimeError('observer input pipe unavailable')
                process.stdin.write(json.dumps(request).encode() + b'\n')
                await process.stdin.drain()
                process.stdin.close()
                reply = await asyncio.wait_for(_json_line(process), min(10, deadline - time.monotonic()))
                if (await process.wait() != 0 or reply.get('nonce') != attempt.nonce or
                        reply.get('round_id') != round_.id):
                    raise RuntimeError('exit observation failed')
                return public_ipv4(reply.get('exit_ip'))
        finally:
            # Remove identity permissions before allowing inode/cgroup reuse.
            await self.gate.remove_probe(attempt, round_)
            group.rmdir()

    async def validate(self, attempt, round_, transport_probe, deadline):
        async def execute():
            exit_ip = await self.observe(attempt, round_, deadline)
            transport_deadline = await transport_probe(attempt)
            executable = trusted_executable(self.config.get('PROTON_EXIT_VALIDATOR', ''))
            response = await bounded_json_command([executable], dict(
                operation='validate', attempt=attempt.to_dict(), round_id=round_.id,
                exit_ip=exit_ip, policy_revision=attempt.policy_revision,
                config_digest=configuration_digest(self.config)), deadline - time.monotonic())
            return parse_evidence(response, round_, exit_ip, now_wall=time.time(), now_mono=time.monotonic(),
                                  transport_deadline=transport_deadline)
        return await asyncio.wait_for(execute(), deadline - time.monotonic())


def _finite(value: Any, minimum=0) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum:
        raise ValueError('invalid evidence time')
    return value


@dataclass(frozen=True)
class Attempt:
    process_identity: str
    generation: int
    nonce: str
    candidate: Mapping[str, Any]
    policy_revision: str
    deadline: float

    def __post_init__(self):
        if (not isinstance(self.process_identity, str) or not 1 <= len(self.process_identity) <= 256 or
                not self.process_identity.isascii() or
                any(ord(c) < 33 for c in self.process_identity) or
                type(self.generation) is not int or self.generation < 0 or
                not isinstance(self.nonce, str) or not HEX.fullmatch(self.nonce) or
                not isinstance(self.policy_revision, str) or not HEX.fullmatch(self.policy_revision)):
            raise ValueError('invalid attempt identity')
        _finite(self.deadline)
        if not isinstance(self.candidate, Mapping):
            raise ValueError('invalid candidate mapping')
        object.__setattr__(self, 'candidate', MappingProxyType(canonical_candidate(dict(self.candidate))))

    def to_dict(self):
        return dict(process_identity=self.process_identity, generation=self.generation,
                    nonce=self.nonce, candidate=dict(self.candidate),
                    policy_revision=self.policy_revision, deadline=self.deadline)


@dataclass(frozen=True)
class ValidationRound:
    id: str
    attempt: Attempt
    acknowledged_mono: float
    fence_max_ttl: int = 90

    def __post_init__(self):
        if (not isinstance(self.id, str) or not HEX.fullmatch(self.id) or
                not isinstance(self.attempt, Attempt) or type(self.fence_max_ttl) is not int or
                self.fence_max_ttl != 90):
            raise ValueError('invalid validation round')
        _finite(self.acknowledged_mono)


def parse_evidence(data, round_, exit_ip, *, now_wall, now_mono, transport_deadline):
    """Convert wall proof once; require coverage of the pre-existing fence."""
    fields = {'attempt', 'round_id', 'exit_ip', 'policy_revision', 'allowed', 'asns',
              'observed_wall', 'expires_wall', 'reason'}
    if (not isinstance(data, dict) or set(data) != fields or
            json.dumps(data.get('attempt'), sort_keys=True, allow_nan=False) !=
            json.dumps(round_.attempt.to_dict(), sort_keys=True, allow_nan=False) or
            data.get('round_id') != round_.id or data.get('exit_ip') != public_ipv4(exit_ip) or
            data.get('policy_revision') != round_.attempt.policy_revision or
            type(data.get('allowed')) is not bool):
        raise ValueError('evidence identity mismatch')
    observed = _finite(data.get('observed_wall'), 1)
    expires = _finite(data.get('expires_wall'), 1)
    if not 0 <= now_wall - observed <= 20 or not observed < expires <= observed + 120:
        raise ValueError('evidence expired or future')
    asns = data.get('asns')
    if (not isinstance(asns, list) or len(asns) > 8 or
            any(type(asn) is not int or not 1 <= asn <= 2**32 - 1 for asn in asns) or
            asns != sorted(set(asns)) or (data['allowed'] and not asns)):
        raise ValueError('invalid authorization ASNs')
    if data.get('reason') not in ('authorized', 'denied', 'unavailable', 'invalid_evidence'):
        raise ValueError('invalid authorization reason')
    if data['allowed'] != (data['reason'] == 'authorized'):
        raise ValueError('inconsistent authorization')
    deadline = now_mono + expires - now_wall
    if not data['allowed']:
        if data['reason'] == 'denied':
            raise AuthorizationDenied('exit policy denied')
        raise ValueError('authorization unavailable')
    if (min(deadline, _finite(transport_deadline)) <
            round_.acknowledged_mono + round_.fence_max_ttl):
        raise ValueError('proof does not cover fence')
    return dict(data, authorization_deadline=deadline, transport_deadline=transport_deadline)
