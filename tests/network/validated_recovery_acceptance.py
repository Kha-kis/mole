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
    proposed = [ipaddress.ip_network(s) for s in ('192.0.2.0/24', '198.51.100.0/24',
                '203.0.113.0/24', '2001:db8::/64')]
    routes = []
    for family in ('-4', '-6'):
        routes.extend(json.loads(command('ip', '-j', family, 'route', 'show', 'table', 'all')))
    namespaces = command('ip', 'netns', 'list').splitlines()
    for line in namespaces:
        name = line.split()[0]
        for family in ('-4', '-6'):
            routes.extend(json.loads(command('ip', '-n', name, '-j', family, 'route', 'show', 'table', 'all')))
    for route in routes:
        destination = route.get('dst', 'default')
        network = ipaddress.ip_network(destination, strict=False) if destination != 'default' else None
        if network is not None and any(p.version == network.version and p.overlaps(network) for p in proposed):
            raise RuntimeError('synthetic subnet overlaps an existing route')
    ids = command('docker', 'network', 'ls', '-q').split()
    if ids:
        for network in json.loads(command('docker', 'network', 'inspect', *ids)):
            for item in network['IPAM'].get('Config') or []:
                subnet = ipaddress.ip_network(item['Subnet']) if item.get('Subnet') else None
                if subnet and any(p.version == subnet.version and p.overlaps(subnet) for p in proposed):
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
if release.get('source'):s.bind((release['source'],0))
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


TLS_ECHO = r'''
import asyncio,json,ssl,sys
state={'mode':'good','requests':0,'sni':[]}
class UDP(asyncio.DatagramProtocol):
    def connection_made(self,t):self.t=t
    def datagram_received(self,d,a):self.t.sendto(d,a)
async def https(r,w):
    try:
        header=await r.readuntil(b'\r\n\r\n')
        state['requests']+=1
        mode=state['mode']
        host=next((v.split(b':',1)[1].strip().decode() for v in header.split(b'\r\n') if v.lower().startswith(b'host:')),'')
        if mode=='hang':await asyncio.sleep(30);return
        code=302 if mode=='redirect' else 200
        ip='9.9.9.9' if mode=='conflict' and host=='ifconfig.co' else '1.1.1.1'
        body=json.dumps({'ip':ip,'padding':'x'*70000 if mode=='oversize' else ''}).encode()
        extra=b'Location: https://api.ipify.org/redirected\r\n' if code==302 else b''
        w.write(('HTTP/1.1 %d Test\r\nContent-Type: application/json\r\nContent-Length: %d\r\n'%(code,len(body))).encode()+extra+b'Connection: close\r\n\r\n'+body)
        await w.drain()
    except Exception:pass
    finally:w.close()
async def main():
    loop=asyncio.get_running_loop()
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[1],sys.argv[2])
    ctx.set_servername_callback(lambda sock,name,context:state['sni'].append(name))
    await loop.create_datagram_endpoint(UDP,local_addr=('0.0.0.0',13001))
    await asyncio.start_server(https,'0.0.0.0',443,ssl=ctx)
    def control():
        request=json.loads(sys.stdin.readline())
        if 'mode' in request:state.update(mode=request['mode'],requests=0,sni=[])
        print(json.dumps(state),flush=True)
    loop.add_reader(sys.stdin.fileno(),control)
    print('ready',flush=True)
    await asyncio.Event().wait()
asyncio.run(main())
'''


async def observer_matrix(name, peer, group, gate, attempt, processes, run, echo):
    from mole_pkg.config import Config
    from mole_pkg.validation import ExitValidator
    fixture = run / 'tmp' / ('tls-' + name)
    fixture.mkdir(mode=0o700)
    certificate, key = fixture / 'ca.pem', fixture / 'key.pem'
    command('openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-subj', '/CN=api.ipify.org', '-addext',
            'subjectAltName=DNS:api.ipify.org,DNS:ifconfig.co', '-days', '1',
            '-keyout', str(key), '-out', str(certificate))
    stop(echo)
    processes.remove(echo)
    server = spawn(peer, TLS_ECHO, certificate, key)
    processes.append(server)
    if line(server) != 'ready':
        raise RuntimeError('TLS observer fixture unavailable')
    original_probe = gate.prepare_probe
    admitted = asyncio.Event()
    async def fixture_probe(value, round_, leaf, targets):
        await original_probe(value, round_, leaf, [{'ip': '192.0.2.2'}])
        admitted.set()
    gate.prepare_probe = fixture_probe
    targets = [dict(host='api.ipify.org', path='/?format=json', ip='8.8.8.8'),
               dict(host='ifconfig.co', path='/json', ip='9.9.9.9')]
    async def resolved(deadline):
        return targets
    config = Config('/nonexistent')
    config._data.update(NETNS_NAME=name, PROTON_VALIDATION_CGROUP_ROOT=str(group))
    results = {}
    try:
        for mode in ('good', 'redirect', 'conflict', 'oversize', 'bad_ca', 'bad_sni', 'hang'):
            server.stdin.write(json.dumps({'mode': mode}) + '\n')
            server.stdin.flush()
            json.loads(line(server))
            # Only this Python test constructor injects a local destination/CA.
            # The production worker and its CLI retain fixed targets and TLS trust.
            code = ('import ssl; import mole_pkg.validation_worker as w; '
                    'original=w.BoundHTTPS; ctx=ssl.create_default_context(' +
                    (')' if mode == 'bad_ca' else 'cafile=' + repr(str(certificate)) + ')') + '; '
                    'w.BoundHTTPS=lambda target,timeout:original(dict(target,ip="192.0.2.2",' +
                    ('host="wrong.invalid",' if mode == 'bad_sni' else '') +
                    '),timeout,context=ctx); raise SystemExit(w.main())')
            validator = ExitValidator(config, gate, _observer_command=[sys.executable, '-B', '-c', code],
                                      _resolve_targets=resolved)
            round_ = await gate.prepare_round(attempt)
            admitted.clear()
            task = asyncio.create_task(validator.observe(attempt, round_, __import__('time').monotonic() + 15))
            if mode == 'hang':
                await asyncio.wait_for(admitted.wait(), 3)
                for _ in range(30):
                    await asyncio.sleep(.05)
                    server.stdin.write('{}\n')
                    server.stdin.flush()
                    if json.loads(line(server))['requests']:
                        break
                else:
                    raise RuntimeError('observer never reached the TLS response wait')
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                else:
                    raise RuntimeError('observer cancellation did not propagate')
                results['cancel_after_admission'] = 'passed'
            else:
                try:
                    observed = await task
                except (RuntimeError, ValueError):
                    if mode == 'good':
                        raise
                    results[mode] = 'rejected'
                else:
                    if mode != 'good' or observed != '1.1.1.1':
                        raise RuntimeError('unsafe observer response was accepted')
                    results[mode] = 'passed'
                server.stdin.write('{}\n')
                server.stdin.flush()
                stats = json.loads(line(server))
                if mode == 'good' and (stats['requests'] != 2 or stats['sni'] != ['api.ipify.org', 'ifconfig.co']):
                    raise RuntimeError('HTTPS SNI or fixed adapter coverage failed')
                if mode == 'redirect' and stats['requests'] != 2:
                    raise RuntimeError('observer followed a redirect')
            if list(group.glob('mole-probe-*')):
                raise RuntimeError('observer cgroup was not cleaned')
            entries = await gate._table()
            if any(entry.get('rule', {}).get('chain') in ('probes_in', 'probes_out') for entry in entries):
                raise RuntimeError('observer allowance remains after completion')
    finally:
        gate.prepare_probe = original_probe
        for path in (certificate, key):
            if path.exists():
                path.unlink()
        fixture.rmdir()
    return results


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


async def packet_matrix(name, peer, client_ns, group, processes, run, quick=False):
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
    command('ip', '-n', peer, 'addr', 'add', '198.51.100.10/32', 'dev', 'peerlink')
    command('ip', '-n', name, 'link', 'set', 'veth-vpn', 'up')
    command('ip', '-n', peer, 'link', 'set', 'peerlink', 'up')
    command('ip', '-n', name, 'route', 'add', '198.51.100.2/32', 'dev', 'veth-vpn')
    command('ip', '-n', name, 'route', 'add', '198.51.100.10/32', 'dev', 'veth-vpn')
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
    api_echo = spawn(name, ECHO.replace("'2001:db8::2'", "'2001:db8::1'"))
    processes.append(api_echo)
    if line(api_echo) != 'ready':
        raise RuntimeError('management API fixture unavailable')
    local_proxy = spawn(name, CLIENT, 65534)
    processes.append(local_proxy)
    line(local_proxy)
    if release(local_proxy, kind='tcp', port=443, address='198.51.100.10') != 'ready':
        raise RuntimeError('management proxy positive control failed')
    send(local_proxy, True)
    local_dns = spawn(name, CLIENT, 65534)
    processes.append(local_dns)
    line(local_dns)
    release(local_dns, kind='udp', port=53, address='198.51.100.10')
    send(local_dns, True)
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
    gate = ValidationGate(name, '198.51.100.10/32')
    original_command = gate._command
    async def diagnosed(script):
        try:
            await original_command(script)
        except RuntimeError:
            diagnostic = subprocess.run(['nsenter', '--net=/run/netns/' + name, '--', 'nft', '-c', '-f', '-'],
                input=script, capture_output=True, text=True, timeout=5)
            if 'missing_chain invalid_expression' not in script:
                print(diagnostic.stderr, file=sys.stderr)
            raise
    gate._command = diagnosed
    await gate.check_support(group)
    value = Attempt(_process_identity(os.getpid()), 1, secrets.token_hex(32),
        dict(name='NL#1', hostname='fixture.example.com', entry_ip='8.8.8.8', exit_ip=None,
             public_key=public[1], port=51820, tier=2,
             features=4, load=0, country='NL'), 'a' * 64, time.monotonic() + 300)
    # Runner-only synthetic construction. Production Attempt/config cannot
    # accept documentation addresses or activate this Python test seam.
    from types import MappingProxyType
    object.__setattr__(value, 'candidate', MappingProxyType(dict(value.candidate, entry_ip='198.51.100.2')))
    await gate.quarantine(value)
    send(local_proxy, False)
    send(local_dns, False)
    new_local = spawn(name, CLIENT, 65534)
    processes.append(new_local)
    line(new_local)
    if release(new_local, kind='tcp', port=443, address='198.51.100.10') != 'connect_failed':
        raise RuntimeError('new management proxy connection bypassed quarantine')
    management = spawn(peer, CLIENT, 0)
    processes.append(management)
    line(management)
    if release(management, kind='tcp', port=13002, address='198.51.100.1', source='198.51.100.10') != 'ready':
        raise RuntimeError('host-to-qBittorrent API management was blocked')
    send(management, True)
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
    observer_results = await observer_matrix(name, peer, group, gate, value, processes, run, echo)
    if quick:
        return dict(complete_matrix=False, mode='quick_no_full_expiry',
                    management_bypass='denied', host_api='passed',
                    packet_gate='passed', cgroup_probe='passed', observer=observer_results)
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
                stale_generation='denied', management_bypass='denied', host_api='passed',
                observer=observer_results, complete_matrix=True)


async def run_syntax(name):
    import base64
    import time
    gate = ValidationGate(name, '192.0.2.254/32')
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
    parser.add_argument('--quick', action='store_true', help='Partial matrix, excluding full expiry; not acceptance')
    args = parser.parse_args()
    preflight(args.run_dir)
    name = 'mole-qa-' + secrets.token_hex(4)
    peer = name + '-p'
    client_ns = name + '-c'
    created = []
    processes = []
    group = Path('/sys/fs/cgroup') / name
    receipt = args.run_dir / 'evidence' / (name + '.json')
    owner = args.run_dir.stat()
    record = dict(owner='operator-approved Mole QA', purpose='isolated Mole synthetic packet acceptance',
                  created_at=__import__('time').time(), namespaces=[name, peer, client_ns],
                  cgroup=str(group), status='starting', quick=args.quick)
    handle = os.fdopen(os.open(receipt, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w+')
    os.fchown(handle.fileno(), owner.st_uid, owner.st_gid)
    json.dump(record, handle)
    handle.flush()
    os.fsync(handle.fileno())
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
        packets = asyncio.run(packet_matrix(name, peer, client_ns, group, processes, args.run_dir, args.quick))
        print(json.dumps(dict(syntax=syntax, packets=packets), sort_keys=True))
        record['result'] = dict(syntax=syntax, packets=packets)
    finally:
        for process in reversed(processes):
            stop(process)
        for namespace in reversed(created):
            command('ip', 'netns', 'delete', namespace)
        if group.exists():
            group.rmdir()
        # Veth creation can fail before either end enters its owned namespace.
        for suffix in ('a', 'b', 'c', 'd'):
            interface = 'vq' + name[-8:] + suffix
            present = subprocess.run(['ip', 'link', 'show', interface], capture_output=True, timeout=5)
            if present.returncode == 0:
                command('ip', 'link', 'delete', interface)
        record['status'] = 'cleaned'
        record['finished_at'] = __import__('time').time()
        # Keep the original descriptor; never reopen an owner-writable path as root.
        handle.seek(0)
        handle.truncate()
        json.dump(record, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()


if __name__ == '__main__':
    main()
