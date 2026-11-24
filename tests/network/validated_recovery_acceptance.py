"""Explicit, synthetic-only kernel acceptance; never imported by unit discovery."""
import argparse
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mole_pkg.network import ValidationGate
from mole_pkg.validation import Attempt
from mole_pkg.utils import _process_identity


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10).stdout


def preflight(run):
    if os.geteuid() != 0 or not (run / 'LIFECYCLE.md').is_file():
        raise RuntimeError('root and an owned QA lifecycle receipt are required')
    # Ignore catch-all routes, but not specific host/VPN routes or Docker subnets.
    proposed = [ipaddress.ip_network(s) for s in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]
    routes = json.loads(command('ip', '-j', '-4', 'route', 'show', 'table', 'all'))
    namespaces = command('ip', 'netns', 'list').splitlines()
    for line in namespaces:
        name = line.split()[0]
        routes.extend(json.loads(command('ip', '-n', name, '-j', '-4', 'route', 'show', 'table', 'all')))
    for route in routes:
        destination = route.get('dst', 'default')
        if destination != 'default' and any(p.overlaps(ipaddress.ip_network(destination, strict=False)) for p in proposed):
            raise RuntimeError('synthetic subnet overlaps an existing route')
    ids = command('docker', 'network', 'ls', '-q').split()
    if ids:
        for network in json.loads(command('docker', 'network', 'inspect', *ids)):
            for item in network['IPAM'].get('Config') or []:
                subnet = ipaddress.ip_network(item['Subnet']) if item.get('Subnet') else None
                if subnet and subnet.version == 4 and any(p.overlaps(subnet) for p in proposed):
                    raise RuntimeError('synthetic subnet overlaps Docker')


CLIENT = r'''
import json,os,socket,sys
uid = int(sys.argv[1])
if uid:
    os.setgroups([]); os.setgid(uid); os.setuid(uid)
print('waiting',flush=True)
release = json.loads(sys.stdin.readline())
kind,port = release['kind'],release['port']
s = socket.socket(socket.AF_INET6 if release.get('ipv6') else socket.AF_INET,
                  socket.SOCK_DGRAM if kind=='udp' else socket.SOCK_STREAM)
if release.get('bind'):s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'mole\0')
s.settimeout(.4)
address = (release.get('address','192.0.2.2'),port)
if kind=='tcp':
    try: s.connect(address)
    except OSError: print('connect_failed',flush=True);sys.exit(0)
print('ready',flush=True)
for line in sys.stdin:
    data=line.strip().encode()
    try:
        if kind=='udp': s.sendto(data,address)
        else: s.sendall(data)
        received=s.recv(4096)
        print(json.dumps({'ok':received==data}),flush=True)
    except OSError: print(json.dumps({'ok':False}),flush=True)
'''


ECHO = r'''
import asyncio,json
class UDP(asyncio.DatagramProtocol):
    def connection_made(self,t):self.t=t
    def datagram_received(self,d,a):
        print(json.dumps({'received':d.decode(errors='replace')}),flush=True);self.t.sendto(d,a)
async def tcp(r,w):
    try:
        while data:=await r.read(4096):
            print(json.dumps({'received':data.decode(errors='replace')}),flush=True)
            w.write(data);await w.drain()
    finally:w.close()
async def main():
    loop=asyncio.get_running_loop()
    await loop.create_datagram_endpoint(UDP,local_addr=('0.0.0.0',13001))
    await loop.create_datagram_endpoint(UDP,local_addr=('0.0.0.0',53))
    await loop.create_datagram_endpoint(UDP,local_addr=('2001:db8::2',13001))
    await asyncio.start_server(tcp,'0.0.0.0',13002)
    await asyncio.start_server(tcp,'0.0.0.0',443)
    print('ready',flush=True)
    await asyncio.Event().wait()
asyncio.run(main())
'''


def spawn(namespace, code, *args):
    return subprocess.Popen(['ip', 'netns', 'exec', namespace, sys.executable, '-B', '-c', code,
                             *map(str, args)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, start_new_session=True)


def stop(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate(timeout=5)


def line(process):
    import select
    ready, _, _ = select.select([process.stdout], [], [], 3)
    if not ready:
        raise RuntimeError('synthetic helper did not respond')
    value = process.stdout.readline().strip()
    if not value:
        raise RuntimeError('synthetic helper exited: ' + process.stderr.read(1024))
    return value


def release(process, **request):
    process.stdin.write(json.dumps(request) + '\n')
    process.stdin.flush()
    return line(process)


def send(process, expected):
    token = 'mole-qa-' + secrets.token_hex(12)
    process.stdin.write(token + '\n')
    process.stdin.flush()
    result = json.loads(line(process))['ok']
    if result is not expected:
        raise RuntimeError('packet positive/negative control failed')


async def packet_matrix(name, peer, client_ns, group, processes, run):
    import time
    first, second = 'vq' + name[-8:] + 'a', 'vq' + name[-8:] + 'b'
    command('ip', 'link', 'add', first, 'type', 'veth', 'peer', 'name', second)
    # Both ends immediately leave the host; they never receive host addresses.
    command('ip', 'link', 'set', first, 'netns', name)
    command('ip', 'link', 'set', second, 'netns', peer)
    command('ip', '-n', name, 'link', 'set', first, 'name', 'veth-vpn')
    command('ip', '-n', peer, 'link', 'set', second, 'name', 'peerlink')
    command('ip', '-n', name, 'addr', 'add', '198.51.100.1/32', 'dev', 'veth-vpn')
    command('ip', '-n', peer, 'addr', 'add', '198.51.100.2/32', 'dev', 'peerlink')
    command('ip', '-n', name, 'link', 'set', 'veth-vpn', 'up')
    command('ip', '-n', peer, 'link', 'set', 'peerlink', 'up')
    command('ip', '-n', name, 'route', 'add', '198.51.100.2/32', 'dev', 'veth-vpn')
    command('ip', '-n', peer, 'route', 'add', '198.51.100.1/32', 'dev', 'peerlink')
    command('ip', '-n', name, 'link', 'set', 'veth-vpn', 'up')
    command('ip', '-n', peer, 'link', 'set', 'peerlink', 'up')
    command('ip', '-n', name, 'link', 'set', 'lo', 'up')
    command('ip', '-n', peer, 'link', 'set', 'lo', 'up')
    private = [command('wg', 'genkey').strip() for _ in range(2)]
    public = [subprocess.run(['wg', 'pubkey'], input=k + '\n', capture_output=True,
                             text=True, check=True, timeout=5).stdout.strip() for k in private]
    fixture_dir = run / 'tmp' / name
    fixture_dir.mkdir(mode=0o700)
    try:
        for index, (namespace, interface, address, allowed, endpoint) in enumerate((
                (name, 'mole', '192.0.2.1/24, 2001:db8::1/64', '0.0.0.0/0, ::/0', '198.51.100.2'),
                (peer, 'wg-peer', '192.0.2.2/24, 2001:db8::2/64',
                 '192.0.2.1/32, 2001:db8::1/128, 203.0.113.0/24', '198.51.100.1'))):
            path = fixture_dir / (interface + '.conf')
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as handle:
                handle.write('[Interface]\nPrivateKey = ' + private[index] + '\nAddress = ' + address +
                    '\nListenPort = 51820\nFwMark = 51820\n[Peer]\nPublicKey = ' + public[1-index] +
                    '\nAllowedIPs = ' + allowed + '\nEndpoint = ' + endpoint + ':51820\nPersistentKeepalive = 1\n')
            command('ip', 'netns', 'exec', namespace, 'wg-quick', 'up', str(path))
    finally:
        for path in fixture_dir.glob('*.conf'):
            path.unlink()
        fixture_dir.rmdir()
    # An independent forwarded client exercises the FORWARD guard.
    first, second = 'vq' + name[-8:] + 'c', 'vq' + name[-8:] + 'd'
    command('ip', 'link', 'add', first, 'type', 'veth', 'peer', 'name', second)
    command('ip', 'link', 'set', first, 'netns', name)
    command('ip', 'link', 'set', second, 'netns', client_ns)
    command('ip', '-n', name, 'link', 'set', first, 'name', 'client-in')
    command('ip', '-n', client_ns, 'link', 'set', second, 'name', 'client-out')
    command('ip', '-n', name, 'addr', 'add', '203.0.113.1/24', 'dev', 'client-in')
    command('ip', '-n', client_ns, 'addr', 'add', '203.0.113.2/24', 'dev', 'client-out')
    command('ip', '-n', name, 'link', 'set', 'client-in', 'up')
    command('ip', '-n', client_ns, 'link', 'set', 'client-out', 'up')
    command('ip', '-n', client_ns, 'route', 'add', '192.0.2.0/24', 'via', '203.0.113.1')
    command('ip', 'netns', 'exec', name, 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
    echo = spawn(peer, ECHO)
    processes.append(echo)
    if line(echo) != 'ready':
        raise RuntimeError('echo listener unavailable')
    clients = []
    for uid, port in ((0, 13002), (65534, 13002), (0, 443)):
        client = spawn(name, CLIENT, uid)
        processes.append(client)
        if line(client) != 'waiting' or release(client, kind='tcp', port=port) != 'ready':
            raise RuntimeError('existing socket positive control failed')
        send(client, True)
        clients.append(client)
    udp = spawn(name, CLIENT, 0)
    processes.append(udp)
    line(udp)
    release(udp, kind='udp', port=13001)
    send(udp, True)
    dns = spawn(name, CLIENT, 65534)
    processes.append(dns)
    line(dns)
    release(dns, kind='udp', port=53)
    send(dns, True)
    forwarded = spawn(client_ns, CLIENT, 0)
    processes.append(forwarded)
    line(forwarded)
    release(forwarded, kind='udp', port=13001)
    send(forwarded, True)
    ipv6 = spawn(name, CLIENT, 0)
    processes.append(ipv6)
    line(ipv6)
    release(ipv6, kind='udp', port=13001, ipv6=True, address='2001:db8::2')
    send(ipv6, True)
    # Leave permissive established/interface rules in a later-priority table.
    command('ip', 'netns', 'exec', name, 'iptables', '-A', 'OUTPUT', '-j', 'ACCEPT')
    command('ip', 'netns', 'exec', name, 'iptables', '-A', 'INPUT', '-j', 'ACCEPT')
    gate = ValidationGate(name, '198.51.100.1/32')
    original_command = gate._command
    async def diagnosed(script):
        try:
            await original_command(script)
        except RuntimeError:
            diagnostic = subprocess.run(['nsenter', '--net=/run/netns/' + name, '--', 'nft', '-c', '-f', '-'],
                input=script, capture_output=True, text=True, timeout=5)
            print(diagnostic.stderr, file=sys.stderr)
            raise
    gate._command = diagnosed
    value = Attempt(_process_identity(os.getpid()), 1, secrets.token_hex(32),
        dict(name='NL#1', hostname='fixture.example.com', entry_ip='8.8.8.8', exit_ip=None,
             public_key=public[1], port=51820, tier=2,
             features=4, load=0, country='NL'), 'a' * 64, time.monotonic() + 300)
    # Runner-only synthetic construction. Production Attempt/config cannot
    # accept documentation addresses or activate this Python test seam.
    from types import MappingProxyType
    object.__setattr__(value, 'candidate', MappingProxyType(dict(value.candidate, entry_ip='198.51.100.2')))
    await gate.quarantine(value)
    for client in clients + [udp, dns, forwarded]:
        send(client, False)
    send(ipv6, False)
    round_ = await gate.prepare_round(value)
    probe = spawn(name, CLIENT, 65534)
    processes.append(probe)
    if line(probe) != 'waiting':
        raise RuntimeError('probe barrier failed')
    (group / 'cgroup.procs').write_text(str(probe.pid))
    membership = Path('/proc/{}/cgroup'.format(probe.pid)).read_text().strip()
    if membership != '0::/' + str(group.relative_to('/sys/fs/cgroup')):
        raise RuntimeError('synthetic cgroup admission failed')
    await gate.prepare_probe(value, round_, group, [{'ip': '192.0.2.2'}])
    # Moving an existing workload socket's process into the group must not
    # retroactively confer the observer's socket-creation identity.
    (group / 'cgroup.procs').write_text(str(clients[-1].pid))
    send(clients[-1], False)
    if release(probe, kind='tcp', port=443, bind=True) != 'ready':
        raise RuntimeError('private probe cgroup could not connect')
    send(probe, True)
    for client in clients + [udp, dns, forwarded]:
        send(client, False)
    await gate.remove_probe(value, round_)
    send(probe, False)
    await gate.authorize(value, round_, dict(attempt=value.to_dict(), round_id=round_.id,
        allowed=True, authorization_deadline=time.monotonic() + 120,
        transport_deadline=time.monotonic() + 120))
    send(udp, True)
    send(forwarded, True)
    await gate.revoke(value)
    send(udp, False)
    # A deliberately late raw grant cannot revive an already expired fence.
    late = await gate.prepare_round(value)
    fence, grant = gate._names(late)
    await gate._command(f'flush set {gate.TABLE} {fence}\n'
                        f'add element {gate.TABLE} {fence} {{ 0 timeout 1s }}\n')
    await asyncio.sleep(1.2)
    await gate._command(gate.grant_rules(late))
    send(udp, False)
    # A failed atomic transaction cannot leave its preceding ACCEPT installed.
    try:
        await gate._command(f'add rule {gate.TABLE} workload accept\n'
                            f'add rule {gate.TABLE} missing_chain invalid_expression\n')
    except RuntimeError:
        pass
    else:
        raise RuntimeError('invalid transaction unexpectedly committed')
    send(udp, False)
    await gate.revoke(value)
    full = await gate.prepare_round(value)
    controller_code = ('import json,subprocess,sys,time; r=json.loads(sys.stdin.readline()); '
        'subprocess.run(["nsenter","--net=/run/netns/"+r["namespace"],"--","nft","-f","-"],'
        'input=r["script"],text=True,check=True,capture_output=True); '
        'print("OPEN",flush=True); time.sleep(300)')
    controller = subprocess.Popen([sys.executable, '-B', '-c', controller_code],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True)
    processes.append(controller)
    controller.stdin.write(json.dumps(dict(namespace=name, script=gate.grant_rules(full))) + '\n')
    controller.stdin.flush()
    if line(controller) != 'OPEN':
        raise RuntimeError('controller positive control failed')
    send(udp, True)
    stop(controller)
    processes.remove(controller)
    # No revocation or rule mutation during this full production-length fence.
    print('Waiting for the 90-second kernel fence with its controller dead.', flush=True)
    await asyncio.sleep(max(0, full.acknowledged_mono + 90.2 - time.monotonic()))
    send(udp, False)
    print('90-second expiry passed; testing a grant after the synthetic proof expires.', flush=True)
    await asyncio.sleep(max(0, full.acknowledged_mono + 120.2 - time.monotonic()))
    await gate._command(gate.grant_rules(full))
    send(udp, False)
    refreshed_data = value.to_dict()
    refreshed_data.update(generation=2, nonce=secrets.token_hex(32),
                          candidate=dict(value.candidate, entry_ip='8.8.8.8'))
    replacement = Attempt(**refreshed_data)
    object.__setattr__(replacement, 'candidate', value.candidate)
    await gate.quarantine(replacement)
    new_round = await gate.prepare_round(replacement)
    try:
        await gate.authorize(value, full, dict(attempt=value.to_dict(), round_id=full.id,
            allowed=True, authorization_deadline=time.monotonic() + 120,
            transport_deadline=time.monotonic() + 120))
    except RuntimeError:
        pass
    else:
        raise RuntimeError('stale attempt reopened a replacement')
    send(udp, False)
    await gate.authorize(replacement, new_round, dict(attempt=replacement.to_dict(), round_id=new_round.id,
        allowed=True, authorization_deadline=time.monotonic() + 120,
        transport_deadline=time.monotonic() + 120))
    send(udp, True)
    await gate.revoke(replacement)
    send(udp, False)
    return dict(existing_root_tcp='denied', existing_nobody_tcp='denied', udp='denied',
                ipv6='denied', probe_cgroup='passed', permit_and_revoke='passed',
                late_grant_after_fence='denied', iptables_interoperation='passed',
                wireguard_and_wg_quick='passed', forwarded_traffic='denied',
                dns_like_packets='denied', unprivileged_bound_probe='passed',
                expiry_test='real_90_seconds_after_controller_death',
                late_grant_after_proof_and_controller_death='denied',
                atomic_partial_failure='denied', inherited_socket='denied',
                stale_generation='denied', complete_matrix=True)


async def run_syntax(name):
    import base64
    import time
    gate = ValidationGate(name, '192.0.2.0/24')
    candidate = dict(name='NL#1', hostname='fixture.example.com', entry_ip='8.8.8.8',
                     exit_ip=None, public_key=base64.b64encode(bytes(range(32))).decode(),
                     port=51820, tier=2, features=4, load=0, country='NL')
    attempt = Attempt(_process_identity(os.getpid()), 1, secrets.token_hex(32), candidate,
                      'a' * 64, time.monotonic() + 90)
    await gate.quarantine(attempt)
    round_ = await gate.prepare_round(attempt)
    await gate.authorize(attempt, round_, dict(attempt=attempt.to_dict(), round_id=round_.id,
                         allowed=True, authorization_deadline=time.monotonic() + 120,
                         transport_deadline=time.monotonic() + 120))
    if not await gate.verify_open(attempt):
        raise RuntimeError('permit failed real kernel readback')
    for _ in range(2):
        round_ = await gate.prepare_round(attempt)
        await gate.authorize(attempt, round_, dict(attempt=attempt.to_dict(), round_id=round_.id,
            allowed=True, authorization_deadline=time.monotonic() + 120,
            transport_deadline=time.monotonic() + 120))
    if len([entry for entry in await gate._table() if 'set' in entry]) > 2:
        raise RuntimeError('old validation rounds leak kernel sets')
    await gate.revoke(attempt)
    if await gate.verify_open(attempt):
        raise RuntimeError('revocation did not close permission')
    return dict(kernel_transactions='passed', packet_acceptance='not_yet_exercised',
                provider_authorization='synthetic')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-dir', required=True, type=Path)
    parser.add_argument('--synthetic-only', action='store_true', required=True)
    args = parser.parse_args()
    preflight(args.run_dir)
    name = 'mole-qa-' + secrets.token_hex(4)
    peer = name + '-p'
    client_ns = name + '-c'
    created = []
    processes = []
    group = Path('/sys/fs/cgroup') / name
    try:
        command('ip', 'netns', 'add', name)
        created.append(name)
        command('ip', 'netns', 'add', peer)
        created.append(peer)
        command('ip', 'netns', 'add', client_ns)
        created.append(client_ns)
        group.mkdir(mode=0o700)
        syntax = asyncio.run(run_syntax(name))
        command('ip', 'netns', 'exec', name, 'nft', 'delete', 'table', 'inet', 'mole_validation')
        packets = asyncio.run(packet_matrix(name, peer, client_ns, group, processes, args.run_dir))
        print(json.dumps(dict(syntax=syntax, packets=packets), sort_keys=True))
    finally:
        for process in reversed(processes):
            stop(process)
        for namespace in reversed(created):
            command('ip', 'netns', 'delete', namespace)
        if group.exists():
            group.rmdir()


if __name__ == '__main__':
    main()
