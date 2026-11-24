"""
MOLE Network Management - Namespace, veth, and iptables utilities
"""

import asyncio
import json
import ipaddress
import os
import re
import sys
import time
import functools
from pathlib import Path
from typing import TYPE_CHECKING

from .utils import log, run_cmd, run_in_netns, async_run_command, async_run_in_netns

if TYPE_CHECKING:
    from .config import Config


def _bounded_gate(method):
    @functools.wraps(method)
    async def bounded(*args, **kwargs):
        return await asyncio.wait_for(method(*args, **kwargs), 5)
    return bounded


class ValidationGate:
    """Single-owner namespace guard. Never edits another table or host rules."""
    TABLE = 'inet mole_validation'

    def __init__(self, netns, management_subnet):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,63}', netns):
            raise ValueError('invalid gate namespace')
        subnet = ipaddress.ip_network(management_subnet)
        if subnet.version != 4 or subnet.prefixlen < 24:
            raise ValueError('invalid management subnet')
        self.netns = netns
        self.management_subnet = str(subnet)
        self.lock = asyncio.Lock()
        self.attempt = None
        self.round = None
        self.deadline = 0
        self._known_rounds = []

    def closed_rules(self):
        commands = [f'add table {self.TABLE}',
                    f'add chain {self.TABLE} workload',
                    f'add chain {self.TABLE} probes_out',
                    f'add chain {self.TABLE} probes_in',
                    f'add chain {self.TABLE} outer_out',
                    f'add chain {self.TABLE} outer_in']
        for hook in ('output', 'input', 'forward'):
            commands.append(f'add chain {self.TABLE} {hook} {{ type filter hook {hook} priority -150; policy drop; }}')
            prefix = f'add rule {self.TABLE} {hook}'
            commands.append(prefix + ' meta nfproto ipv6 counter drop')
            if hook != 'forward':
                direction = 'oifname' if hook == 'output' else 'iifname'
                address = 'daddr' if hook == 'output' else 'saddr'
                commands.append(prefix + f' {direction} "lo" accept')
                commands.append(prefix + f' {direction} "veth-vpn" ip {address} {self.management_subnet} accept')
                commands.append(prefix + ' jump outer_' + ('out' if hook == 'output' else 'in'))
                commands.append(prefix + ' jump probes_' + ('out' if hook == 'output' else 'in'))
            commands.append(prefix + ' jump workload')
            commands.append(prefix + ' counter drop')
        return '\n'.join(commands) + '\n'

    async def check_support(self, root):
        """Kernel validation only; do not commit a table during preflight."""
        import secrets
        relative = Path(root).relative_to('/sys/fs/cgroup')
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', str(relative)):
            raise RuntimeError('unsupported probe cgroup path')
        table = 'inet mole_check_' + secrets.token_hex(8)
        script = self.closed_rules().replace(self.TABLE, table)
        script += (f'add set {table} fence {{ type mark; flags timeout; timeout 90s; }}\n'
                   f'add rule {table} probes_out meta mark & 0x0 @fence '
                   f'socket cgroupv2 level {len(relative.parts)} "{relative}" accept\n')
        result = await async_run_command(['nsenter', '--net=/run/netns/' + self.netns, '--',
            'nft', '--check', '-f', '-'], 5, input_data=script.encode())
        if result.returncode:
            raise RuntimeError('validated recovery enforcement unsupported')

    def peer_rules(self, attempt):
        address, port = attempt.candidate['entry_ip'], attempt.candidate['port']
        return (f'flush chain {self.TABLE} outer_out\nflush chain {self.TABLE} outer_in\n'
                f'add rule {self.TABLE} outer_out oifname "veth-vpn" ip daddr {address} '
                f'udp dport {port} meta mark 51820 accept\n'
                f'add rule {self.TABLE} outer_in iifname "veth-vpn" ip saddr {address} '
                f'udp sport {port} ct state established accept\n')

    @staticmethod
    def _names(round_):
        return 'f_' + round_.id[:24], 'g_' + round_.id[:24]

    def round_rules(self, round_):
        fence, grant = self._names(round_)
        return (f'add set {self.TABLE} {fence} {{ type mark; flags timeout; timeout 90s; }}\n'
                f'add element {self.TABLE} {fence} {{ 0 timeout 90s }}\n'
                f'add set {self.TABLE} {grant} {{ type mark; flags timeout; timeout 90s; }}\n')

    def grant_rules(self, round_):
        fence, grant = self._names(round_)
        commands = [f'add element {self.TABLE} {grant} {{ 0 timeout 90s }}',
                    f'flush chain {self.TABLE} workload']
        # A late grant has no effect after the independently established fence.
        for direction in ('oifname', 'iifname'):
            commands.append(f'add rule {self.TABLE} workload {direction} "mole" '
                            f'meta mark & 0x0 @{fence} meta mark & 0x0 @{grant} counter accept')
        return '\n'.join(commands) + '\n'

    async def _command(self, script):
        # ip-netns-exec remounts sysfs and hides cgroup v2 on some hosts.
        # Enter only the network namespace so nft can resolve the private leaf.
        result = await async_run_command(['nsenter', '--net=/run/netns/' + self.netns, '--', 'nft', '-f', '-'],
                                         5, input_data=script.encode())
        if result.returncode:
            raise RuntimeError('validation gate mutation failed')

    async def _table(self):
        result = await async_run_command(['nsenter', '--net=/run/netns/' + self.netns, '--',
                                          'nft', '-j', 'list', 'table', 'inet', 'mole_validation'], 5)
        if result.returncode:
            raise RuntimeError('validation gate verification failed')
        return json.loads(result.stdout)['nftables']

    async def _verify_base(self):
        entries = await self._table()
        chains = {x['chain']['name']: x['chain'] for x in entries if 'chain' in x}
        for hook in ('output', 'input', 'forward'):
            chain = chains.get(hook, {})
            if chain.get('policy') != 'drop' or chain.get('prio') != -150 or chain.get('hook') != hook:
                raise RuntimeError('validation gate is not fail closed')
        return entries

    def _current(self, attempt):
        if self.attempt is None or self.attempt != attempt:
            raise RuntimeError('stale validation gate owner')

    @_bounded_gate
    async def quarantine(self, attempt):
        async with self.lock:
            self.deadline = 0
            # Atomic replacement closes an old controller's permissions too.
            result = await async_run_in_netns(['nft', 'list', 'table', 'inet', 'mole_validation'],
                                               self.netns, 5)
            script = (f'delete table {self.TABLE}\n' if result.returncode == 0 else '') + self.closed_rules()
            await self._command(script)
            await self._verify_base()
            self.attempt, self.round = attempt, None
            self._known_rounds = []
            if attempt is not None:
                await self._command(self.peer_rules(attempt))

    @_bounded_gate
    async def prepare_round(self, attempt):
        from .validation import ValidationRound
        import secrets
        async with self.lock:
            self._current(attempt)
            round_ = ValidationRound(secrets.token_hex(32), attempt, 0)
            await self._command(self.round_rules(round_))
            acknowledged = time.monotonic()
            round_ = ValidationRound(round_.id, attempt, acknowledged)
            await self._verify_base()
            self.round = round_
            self._known_rounds.append(round_)
            return round_

    @_bounded_gate
    async def authorize(self, attempt, round_, evidence):
        async with self.lock:
            self._current(attempt)
            if (round_ is None or self.round != round_ or evidence.get('attempt') != attempt.to_dict() or
                    evidence.get('round_id') != round_.id or evidence.get('allowed') is not True or
                    min(evidence.get('authorization_deadline', 0), evidence.get('transport_deadline', 0)) <
                    round_.acknowledged_mono + 90 or time.monotonic() >= round_.acknowledged_mono + 90):
                raise RuntimeError('invalid gate evidence')
            await self._command(self.grant_rules(round_))
            entries = await self._verify_base()
            names = self._names(round_)
            for name in names:
                sets = [x['set'] for x in entries if 'set' in x and x['set'].get('name') == name]
                if len(sets) != 1 or not sets[0].get('elem'):
                    raise RuntimeError('validation permit not verified')
            self.deadline = round_.acknowledged_mono + 90
            keep = set(self._names(round_)) | {'p_' + round_.id[:24]}
            obsolete = [entry['set']['name'] for entry in entries if 'set' in entry and
                        re.fullmatch(r'[fgp]_[0-9a-f]{24}', entry['set'].get('name', '')) and
                        entry['set']['name'] not in keep]
            if obsolete:
                await self._command(''.join(f'delete set {self.TABLE} {name}\n' for name in obsolete))
            self._known_rounds = [round_]

    @_bounded_gate
    async def prepare_probe(self, attempt, round_, group, targets):
        # The caller's fixed-adapter validator enforces global destinations.
        # This low-level packet primitive also serves isolated synthetic tests.
        addresses = [str(ipaddress.IPv4Address(target['ip'])) for target in targets]
        if not 1 <= len(addresses) <= 2:
            raise ValueError('invalid probe destinations')
        relative = Path(group).relative_to('/sys/fs/cgroup')
        path = str(relative)
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', path) or '..' in relative.parts:
            raise ValueError('invalid observer cgroup')
        name = 'p_' + round_.id[:24]
        async with self.lock:
            self._current(attempt)
            if self.round != round_:
                raise RuntimeError('stale probe round')
            elements = ', '.join(address + ' timeout 20s' for address in addresses)
            script = (f'add set {self.TABLE} {name} {{ type ipv4_addr; flags timeout; timeout 20s; }}\n'
                      f'add element {self.TABLE} {name} {{ {elements} }}\n'
                      f'flush chain {self.TABLE} probes_out\nflush chain {self.TABLE} probes_in\n'
                      f'add rule {self.TABLE} probes_out oifname "mole" ip daddr @{name} '
                      f'tcp dport 443 socket cgroupv2 level {len(relative.parts)} "{path}" '
                      f'ct mark set 0x4d4f4c45 counter accept\n'
                      f'add rule {self.TABLE} probes_in iifname "mole" ip saddr @{name} '
                      f'tcp sport 443 ct state established ct mark 0x4d4f4c45 counter accept\n')
            await self._command(script)
            await self._verify_base()

    @_bounded_gate
    async def remove_probe(self, attempt, round_):
        async with self.lock:
            self._current(attempt)
            if self.round != round_:
                raise RuntimeError('stale probe cleanup')
            await self._command(f'flush chain {self.TABLE} probes_out\n'
                                f'flush chain {self.TABLE} probes_in\n')

    @_bounded_gate
    async def revoke(self, attempt):
        async with self.lock:
            self._current(attempt)
            self.deadline = 0
            await self._command(f'flush chain {self.TABLE} workload\n'
                                f'flush chain {self.TABLE} probes_out\n'
                                f'flush chain {self.TABLE} probes_in\n')
            await self._verify_base()
            self.round = None

    @_bounded_gate
    async def verify_open(self, attempt):
        async with self.lock:
            self._current(attempt)
            if not self.round or time.monotonic() >= self.deadline:
                return False
            entries = await self._verify_base()
            for name in self._names(self.round):
                if not any(x.get('set', {}).get('name') == name and x['set'].get('elem') for x in entries):
                    return False
            return True


def disable_ipv6_in_namespace(netns: str) -> None:
    """Disable IPv6 inside the namespace to prevent leaks.

    PIA does not support IPv6, so all IPv6 traffic must be blocked
    to prevent leaks outside the VPN tunnel.
    """
    log.info("Disabling IPv6 in namespace...")

    # Disable IPv6 on all interfaces in namespace
    run_in_netns([
        "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"
    ], netns, check=False)
    run_in_netns([
        "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"
    ], netns, check=False)

    # Also block IPv6 with ip6tables as defense in depth
    run_in_netns(["ip6tables", "-P", "INPUT", "DROP"], netns, check=False)
    run_in_netns(["ip6tables", "-P", "OUTPUT", "DROP"], netns, check=False)
    run_in_netns(["ip6tables", "-P", "FORWARD", "DROP"], netns, check=False)

    log.debug("IPv6 disabled in namespace")


def setup_namespace(config: "Config") -> None:
    """Setup network namespace and veth pair"""
    netns = config.netns

    # Create namespace if needed
    result = run_cmd(["ip", "netns", "list"], check=False)
    if netns not in [line.split()[0] for line in result.stdout.splitlines() if line.split()]:
        log.info(f"Creating network namespace '{netns}'...")
        run_cmd(["ip", "netns", "add", netns])

    # Protect the namespace before bringing an external link or NAT online.
    setup_killswitch(config)
    disable_ipv6_in_namespace(netns)

    # Create veth pair if needed
    result = run_cmd(["ip", "link", "show", "veth-host"], check=False)
    if result.returncode != 0:
        log.info("Creating veth pair...")
        run_cmd(["ip", "link", "add", "veth-host", "type", "veth", "peer", "name", "veth-vpn"])
        run_cmd(["ip", "link", "set", "veth-vpn", "netns", netns])
        run_cmd(["ip", "addr", "add", f"{config.veth_host_ip}/24", "dev", "veth-host"])
        run_cmd(["ip", "link", "set", "veth-host", "up"])
        run_in_netns(["ip", "addr", "add", f"{config.veth_vpn_ip}/24", "dev", "veth-vpn"], netns)
        run_in_netns(["ip", "link", "set", "veth-vpn", "up"], netns)
        run_in_netns(["ip", "link", "set", "lo", "up"], netns)

    # Enable IP forwarding
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1")

    # Setup NAT masquerade
    masq_check = run_cmd([
        "iptables", "-t", "nat", "-C", "POSTROUTING",
        "-s", "10.200.200.0/24", "-o", config.host_interface,
        "-j", "MASQUERADE"
    ], check=False)

    if masq_check.returncode != 0:
        run_cmd([
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", "10.200.200.0/24", "-o", config.host_interface,
            "-j", "MASQUERADE"
        ])



async def async_setup_namespace(config: "Config") -> None:
    request = dict(netns=config.netns, veth_host_ip=config.veth_host_ip,
                   veth_vpn_ip=config.veth_vpn_ip, host_interface=config.host_interface)
    env = dict(os.environ)
    env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1]) + os.pathsep + env.get('PYTHONPATH', '')
    result = await async_run_command([sys.executable, '-m', 'mole_pkg.network_worker'],
                                     120, env=env, input_data=json.dumps(request).encode())
    if result.returncode != 0:
        raise RuntimeError('namespace setup failed')


async def async_allow_vpn_server_ip(config: "Config", server_ip: str,
                                   old_server_ip: str = None) -> None:
    async def command(args, required=True):
        result = await async_run_in_netns(args, config.netns, timeout=10)
        if required and result.returncode != 0:
            raise RuntimeError('VPN endpoint policy failed')
        return result

    if old_server_ip and old_server_ip != server_ip:
        rule = ['OUTPUT', '-o', 'veth-vpn', '-d', old_server_ip, '-j', 'ACCEPT']
        # Remove all old duplicates, but bound reconciliation even if the ruleset
        # is being changed by an unexpected writer.
        for _ in range(32):
            if (await command(['iptables', '-C'] + rule, False)).returncode != 0:
                break
            await command(['iptables', '-D'] + rule)
        else:
            raise RuntimeError('VPN endpoint policy did not converge')
    rule = ['OUTPUT', '-o', 'veth-vpn', '-d', server_ip, '-j', 'ACCEPT']
    if (await command(['iptables', '-C'] + rule, False)).returncode != 0:
        await command(['iptables', '-I', 'OUTPUT', '3'] + rule[1:])
    await command(['iptables', '-C'] + rule)


async def async_disconnect_vpn(config: "Config") -> None:
    await async_run_in_netns(['wg-quick', 'down', config.wg_conf], config.netns, timeout=30)


def setup_killswitch(config: "Config") -> None:
    """Setup kill switch iptables rules inside the namespace.

    This function is idempotent - it always flushes and reapplies rules
    to ensure they match the current version's expected configuration.
    """
    netns = config.netns
    log.info("Setting up kill switch...")

    # Keep rule rebuilds fail-closed, including the interval after flushing.
    run_in_netns(["iptables", "-P", "OUTPUT", "DROP"], netns)
    run_in_netns(["iptables", "-P", "INPUT", "DROP"], netns)

    # Always flush and reapply rules (idempotent)
    # This ensures rules are always correct even after upgrades
    run_in_netns(["iptables", "-F", "OUTPUT"], netns, check=False)
    run_in_netns(["iptables", "-F", "INPUT"], netns, check=False)

    # Allow loopback
    run_in_netns([
        "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"
    ], netns, check=False)
    run_in_netns([
        "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"
    ], netns, check=False)

    # Allow traffic on veth-vpn ONLY to local subnet (10.200.200.0/24)
    # This prevents leaks - traffic cannot route to internet via veth
    # VPN server IP will be added separately by allow_vpn_server_ip()
    run_in_netns([
        "iptables", "-A", "OUTPUT", "-o", "veth-vpn",
        "-d", "10.200.200.0/24", "-j", "ACCEPT"
    ], netns, check=False)
    run_in_netns([
        "iptables", "-A", "INPUT", "-i", "veth-vpn",
        "-s", "10.200.200.0/24", "-j", "ACCEPT"
    ], netns, check=False)

    # Allow traffic on mole (WireGuard) interface
    run_in_netns([
        "iptables", "-A", "OUTPUT", "-o", "mole", "-j", "ACCEPT"
    ], netns, check=False)
    run_in_netns([
        "iptables", "-A", "INPUT", "-i", "mole", "-j", "ACCEPT"
    ], netns, check=False)

    # Allow established/related connections
    run_in_netns([
        "iptables", "-A", "INPUT", "-m", "state",
        "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
    ], netns, check=False)

    # The marker must drop, never unconditionally accept before the final drop.
    run_in_netns([
        "iptables", "-A", "OUTPUT", "-m", "comment",
        "--comment", "mole-killswitch", "-j", "DROP"
    ], netns, check=False)

    # Drop everything else (kill switch)
    run_in_netns([
        "iptables", "-A", "OUTPUT", "-j", "DROP"
    ], netns, check=False)
    run_in_netns([
        "iptables", "-A", "INPUT", "-j", "DROP"
    ], netns, check=False)

    log.info("Kill switch enabled - traffic blocked if VPN drops")


def allow_vpn_server_ip(config: "Config", server_ip: str, old_server_ip: str = None) -> None:
    """Add iptables rule to allow traffic to VPN server IP via veth-vpn.

    This must be called before connecting to the VPN so WireGuard UDP
    packets can reach the server through the veth pair.
    """
    netns = config.netns

    # Remove old server IP rule if switching servers
    if old_server_ip and old_server_ip != server_ip:
        log.debug(f"Removing old server IP rule: {old_server_ip}")
        run_in_netns([
            "iptables", "-D", "OUTPUT", "-o", "veth-vpn",
            "-d", old_server_ip, "-j", "ACCEPT"
        ], netns, check=False)

    # Check if rule already exists
    result = run_in_netns([
        "iptables", "-C", "OUTPUT", "-o", "veth-vpn",
        "-d", server_ip, "-j", "ACCEPT"
    ], netns, check=False)

    if result.returncode != 0:
        # Rule doesn't exist, add it
        # Insert after local subnet rule but before the DROP rule
        log.info(f"Allowing VPN server IP: {server_ip}")
        run_in_netns([
            "iptables", "-I", "OUTPUT", "3", "-o", "veth-vpn",
            "-d", server_ip, "-j", "ACCEPT"
        ], netns, check=False)


def cleanup_namespace(netns: str) -> None:
    """Cleanup network namespace and related interfaces"""
    log.info(f"Cleaning up namespace '{netns}'...")

    # Delete veth pair (this automatically removes both ends)
    run_cmd(["ip", "link", "del", "veth-host"], check=False)

    # Delete namespace
    run_cmd(["ip", "netns", "del", netns], check=False)


def connect_vpn(config: "Config", server_ip: str, server_vip: str, old_server_ip: str = None) -> bool:
    """Establish VPN connection"""
    log.info("Connecting VPN...")

    netns = config.netns

    # Bring down existing connection
    run_in_netns(["wg-quick", "down", "mole"], netns, check=False)

    # Allow traffic to VPN server IP through the kill switch
    allow_vpn_server_ip(config, server_ip, old_server_ip)

    # Update routes
    if old_server_ip:
        run_in_netns(["ip", "route", "del", old_server_ip, "via", config.veth_host_ip], netns, check=False)

    run_in_netns([
        "ip", "route", "add", server_ip,
        "via", config.veth_host_ip, "dev", "veth-vpn"
    ], netns, check=False)

    # Bring up WireGuard
    from .utils import sanitize_for_log
    result = run_in_netns(["wg-quick", "up", config.wg_conf], netns, check=False)
    if result.returncode != 0:
        log.error(f"Failed to bring up WireGuard: {sanitize_for_log(result.stderr)}")
        return False

    # Verify connection
    result = run_in_netns(["ping", "-c", "1", "-W", "5", server_vip], netns, check=False)
    if result.returncode != 0:
        log.warning("VPN connectivity check failed, but continuing...")

    log.info("VPN connected")
    return True


def disconnect_vpn(config: "Config") -> None:
    """Disconnect VPN"""
    log.info("Disconnecting VPN...")
    run_in_netns(["wg-quick", "down", config.wg_conf], config.netns, check=False)
