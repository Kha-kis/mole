# MOLE - Managed Obfuscated Link Environment

A VPN tunnel manager with automatic port forwarding and torrent client integration.

MOLE runs your VPN connection in an isolated network namespace, automatically handles token renewal, port forwarding keepalive, and updates your torrent client's listening port.

## Features

- **Network Namespace Isolation** - VPN traffic is isolated from host network
- **Kill Switch** - Blocks all traffic if VPN connection drops
- **DNS over TLS** - Encrypted DNS with caching, filtering, and auto-updating blocklists
- **HTTP Proxy** - Authenticated proxy to route traffic through VPN
- **HTTP Control API** - REST API to query/control VPN state
- **Automatic Token Renewal** - Refreshes VPN credentials before expiration
- **Port Forwarding** - Automatically requests and maintains forwarded ports
- **Torrent Client Integration** - Updates qBittorrent's listening port via API
- **Health Monitoring** - Watchdog detects and recovers from connection failures
- **Systemd Integration** - Runs as a proper system service
- **Server Stickiness** - Remembers and prefers last working server
- **Multi-Region Fallback** - Comma-separated region/country list for failover
- **Latency-Based Selection** - Choose servers based on ping time
- **Speed Testing** - Test VPN connection speed
- **Bandwidth Statistics** - Track upload/download usage over time

## Supported Providers

### PIA (Private Internet Access)
- Port forwarding with 60-day persistence
- Dedicated IP support
- Latency-based server selection
- Multi-region fallback
- IPv6 leak prevention

### ProtonVPN
- WireGuard protocol
- Port forwarding via NAT-PMP (Plus plan required)
- NetShield DNS filtering (malware, ads, trackers)
- Multi-country fallback
- Latency-based server selection
- Server stickiness (remembers last server)
- Certificate persistence (1-year validity)

## Supported Torrent Clients

- **qBittorrent** - Via Web API

## Requirements

### Required
- Linux with network namespace support
- WireGuard (`wireguard-tools`)
- Python 3.8+
- curl
- Root access (for network namespace management)

### For ProtonVPN
- `proton-client` Python package (`pip3 install proton-client`)
- `natpmpc` for port forwarding (`apt install natpmpc`)

## Installation

```bash
git clone https://github.com/yourusername/mole.git
cd mole
sudo ./install.sh
```

The installer will:
- Check and install required dependencies (wireguard-tools, curl, etc.)
- Install the `mole` command to `/usr/local/bin/`
- Install the systemd service
- Run interactive setup wizard
- Auto-detect best server/region
- Start the VPN service

## Upgrading

For an in-place upgrade on a configured host, use `--upgrade`:

```bash
git pull
sudo ./install.sh --upgrade
sudo systemctl restart mole
```

`--upgrade` mirrors `mole_pkg/` into `/usr/local/lib/mole/` (deletions
in the repo are propagated via `rsync --delete` so old modules don't
linger), reinstalls the systemd unit, and **stops short of starting
the service** so you can review the change before cutting over. It
skips dependency installation and the interactive `mole init` wizard.

After restart, allow up to ~3 minutes for the watchdog VPN-renewal
cycle if the first reconnect attempt races with `wg-quick`.

## Uninstallation

```bash
sudo ./uninstall.sh
```

The uninstaller will:
- Stop and disable `qbittorrent-mole` service (if installed)
- Stop and disable `mole` service
- Remove the binary and service files
- Optionally remove configuration and state files

**Note:** The network namespace and veth interfaces are preserved. To remove manually:
```bash
sudo ip link del veth-host
sudo ip netns del vpn
```

## Configuration

The setup wizard (`mole init`) will guide you through configuration. You can also edit `/etc/mole/config` directly.

### PIA Configuration

```ini
VPN_PROVIDER=pia

# PIA Credentials
PIA_USER=your_username
PIA_PASS=your_password

# Region (or comma-separated fallback list, tried in order)
PIA_REGION=ca_toronto,ca_montreal,us_chicago

# Specific server (optional, overrides auto-selection)
# PIA_SERVER=toronto420

# Dedicated IP token (optional)
# PIA_DIP_TOKEN=dip_xxxxxxxxxxxxxxxx

# Max latency threshold (optional, in ms)
# PIA_MAX_LATENCY=100

# Port Forwarding
PORT_FORWARD=true
```

### ProtonVPN Configuration

```ini
VPN_PROVIDER=proton

# ProtonVPN Credentials (your Proton account)
PROTON_USER=your_email@example.com
PROTON_PASS=your_password

# Account tier (0=free, 1=basic, 2=plus/visionary)
PROTON_TIER=2

# Country (or comma-separated fallback list, tried in order)
# Use 2-letter codes: US, NL, CH, DE, etc.
PROTON_COUNTRY=NL,DE,CH

# Specific server (optional)
# PROTON_SERVER=NL#458

# Max latency threshold (optional, in ms)
# PROTON_MAX_LATENCY=100

# NetShield DNS filtering (Plus plan only)
# 0=off, 1=block malware, 2=block malware+ads+trackers
PROTON_NETSHIELD=2

# Prefer reconnecting to last used server (default: true)
PROTON_PREFER_LAST_SERVER=true

# Port Forwarding (requires Plus plan)
PORT_FORWARD=true

# Optional. Default for VPN_PROVIDER=proton is 45 (NAT-PMP TTL ~60s);
# default for PIA is 900 (long-lived signed-payload model). Set
# explicitly only to override the provider-aware default.
# KEEPALIVE_INTERVAL=45
```

### Common Settings

```ini
# Network Namespace
NETNS_NAME=vpn
VETH_HOST_IP=10.200.200.1
VETH_VPN_IP=10.200.200.2

# Host network interface (for NAT)
HOST_INTERFACE=eth0

# Torrent Client (qbittorrent or none)
TORRENT_CLIENT=qbittorrent
QB_PORT=8080
QB_USER=youruser

# qBittorrent WebUI request timeout in seconds (default: 15)
# Raise this if you have many torrents (10k+) and see repeated
# "qBittorrent connection-status timed out" warnings — qBit's WebUI
# is single-threaded and occasionally pauses under heavy state load.
# QB_API_TIMEOUT=15

# Whether to write `DNS = ...` into the generated WireGuard config.
# Default: false. With the standard netns layout, /etc/resolv.conf is
# bind-mounted from /etc/netns/<NS>/resolv.conf, which makes wg-quick's
# resolvconf hook fail (`mv: cannot move ...`). The interface comes up,
# resolvconf fails, wg-quick tears it back down, and mole's watchdog
# spends the next ~3 minutes recovering — repeated daily on renewal.
# Set to true ONLY when running mole without netns isolation.
# WG_DNS_IN_CONF=false
```

## Usage

### Start the service

```bash
sudo systemctl start mole
```

### Check status

```bash
sudo mole status
```

### View logs

```bash
sudo mole logs -f
```

### Force new server selection

```bash
# For ProtonVPN - forces selection of a new server on next restart
sudo touch /var/lib/mole/new-server
sudo systemctl restart mole
```

### Commands

```
mole --version       Show version
mole validate        Validate configuration file
mole ip              Show current public IP through VPN
mole dns             Test DNS over TLS functionality
sudo mole dns -n     Test DNS from inside VPN namespace
mole api-key generate  Generate a new API key
sudo mole api-key show Show current API key status
mole regions [provider] [--pf] [--servers]  List VPN regions/countries
mole autoselect [-s] [-r REGION]  Find fastest region/country
mole speedtest       Test VPN connection speed
mole stats [--save]  Show bandwidth statistics
sudo mole init       Initialize directory structure (or reconfigure)
sudo mole status     Show VPN connection status
sudo mole qbittorrent setup    Setup qBittorrent in VPN namespace
sudo mole qbittorrent start    Start qBittorrent service
sudo mole qbittorrent stop     Stop qBittorrent service
mole qbittorrent status        Check qBittorrent status
sudo mole start      Start the VPN service
sudo mole restart    Force VPN reconnection
sudo mole stop       Stop the VPN service
sudo mole logs       Show service logs (use -f to follow)
sudo mole run        Run the VPN manager (used by systemd)
```

## Provider-Specific Features

### PIA Features

#### Dedicated IP
If you have a PIA Dedicated IP, configure it with your DIP token:
```ini
PIA_DIP_TOKEN=dip_xxxxxxxxxxxxxxxx
```

#### Port Forwarding Persistence
MOLE automatically persists your forwarded port for up to 60 days. The port signature is saved and reused across restarts.

### ProtonVPN Features

#### Server Stickiness
By default, MOLE remembers the last working server and reconnects to it:
```ini
PROTON_PREFER_LAST_SERVER=true  # default
```

To force a new server selection:
```bash
sudo touch /var/lib/mole/new-server
sudo systemctl restart mole
```

#### NetShield DNS Filtering
ProtonVPN Plus users can enable NetShield for DNS-based filtering:
```ini
PROTON_NETSHIELD=0  # Off
PROTON_NETSHIELD=1  # Block malware
PROTON_NETSHIELD=2  # Block malware + ads + trackers
```

#### Certificate Persistence
ProtonVPN certificates are valid for 1 year and are automatically reused across restarts. The certificate is stored in `/var/lib/mole/proton_certificate.json`.

#### Port Change Notifications
When using NAT-PMP port forwarding, MOLE warns you if your port changes:
```
[WARNING] Port changed: 51322 -> 63526 (update your applications)
```

## Directory Structure

```
/etc/mole/
  config              Configuration file
  providers/
    pia-ca.crt        PIA CA certificate

/var/lib/mole/        Runtime state files
  server_name         Last used server (for stickiness)
  proton_session.json ProtonVPN session data
  proton_certificate.json  ProtonVPN certificate
  pf-response.json    PIA port forward signature
  port                Current forwarded port

/etc/wireguard/
  mole.conf           WireGuard configuration (auto-generated)
```

## qBittorrent Integration

MOLE can automatically set up qBittorrent to run inside the VPN namespace.

### Quick Setup

```bash
# 1. Start MOLE
sudo systemctl start mole

# 2. Setup qBittorrent service
sudo mole qbittorrent setup

# This will:
# - Detect any existing qBittorrent service and offer to disable it
# - Create a new systemd service that runs qBittorrent in the VPN namespace
# - Optionally start and enable the service
```

### Managing qBittorrent

```bash
sudo mole qbittorrent start    # Start qBittorrent
sudo mole qbittorrent stop     # Stop qBittorrent
sudo mole qbittorrent status   # Check status
sudo mole qbittorrent enable   # Enable on boot
sudo mole qbittorrent disable  # Disable on boot
```

### Localhost Access

By default, qBittorrent is accessible at `http://10.200.200.2:8080`. To also access it at `http://localhost:8080`:

```bash
sudo mole qbittorrent passthrough
```

## Running Other Applications Through VPN

To run any application through the VPN namespace:

```bash
sudo ip netns exec vpn <command>
```

## Security Features

### Kill Switch

The kill switch uses iptables rules inside the network namespace to prevent IP leaks if the VPN connection drops.

**What gets blocked:**
- All internet traffic if the VPN tunnel goes down
- Any attempt to route traffic outside the VPN

**What remains allowed:**
- VPN tunnel traffic (mole interface)
- Host communication via veth (10.200.200.x)
- Loopback traffic

### IPv6 Leak Prevention

IPv6 is automatically disabled inside the VPN namespace to prevent leaks.

### DNS Leak Protection

DNS queries from applications in the namespace are forced through the VPN tunnel. When DNS over TLS is enabled, queries are encrypted end-to-end.

### Network Isolation

The VPN runs in a separate network namespace, completely isolated from your host's network stack.

## DNS over TLS

MOLE can run a DNS over TLS server that encrypts your DNS queries and optionally blocks ads, malware, and tracking domains.

The resolver pools persistent TLS connections to each upstream so individual queries don't pay a TCP+TLS handshake. Concurrent identical queries are collapsed via singleflight — only one upstream call goes out, all callers receive the same response. With a comma-separated `DOT_UPSTREAM` list, queries failover to the next upstream after `DOT_QUERY_RETRIES` attempts on the current one.

### Configuration

```ini
DOT_ENABLED=true

# Upstream(s) — built-in: cloudflare, cloudflare-family, quad9, google, custom
# Comma-separated for failover (tried in order, per query)
DOT_UPSTREAM=cloudflare
# DOT_UPSTREAM=cloudflare,quad9     # failover example

# Custom upstream (only when DOT_UPSTREAM includes 'custom')
# DOT_CUSTOM_SERVER=10.0.0.1:853    # connect target (ip:port or hostname:port)
# DOT_CUSTOM_SNI=dns.example.com    # optional: SNI for cert validation
#
# Use DOT_CUSTOM_SNI when DOT_CUSTOM_SERVER is a literal IP — connect by IP
# (no DNS lookup at startup) but still validate the upstream's certificate
# against the named hostname. This is required when mole's own resolver is
# the only resolver available in the namespace, since looking up the upstream
# hostname would otherwise create a bootstrap-circular dependency.

# Connection pool (per upstream)
DOT_POOL_SIZE=2                     # persistent TLS connections kept open
DOT_QUERY_TIMEOUT=2.0               # per-attempt upstream query timeout (s)
DOT_QUERY_RETRIES=2                 # retries per upstream before failover
DOT_RETRY_BACKOFF_MS=200            # backoff between retries (ms)

# Filtering
DOT_BLOCK_ADS=true
DOT_BLOCK_MALWARE=true

# Caching
DOT_CACHING=true
DOT_UPDATE_PERIOD=24h
```

Real-time pool state, per-upstream counters, and latency percentiles are exposed at `GET /v1/dns` (see HTTP Control API section below).

## HTTP Proxy

MOLE can run an authenticated HTTP proxy that routes traffic through the VPN.

### Configuration

```ini
PROXY_ENABLED=true
PROXY_PORT=8888
PROXY_USER=mole
PROXY_PASS=your_secure_password
```

### Usage

```bash
curl -x http://mole:password@10.200.200.1:8888 https://ifconfig.me
```

## HTTP Control API

MOLE can expose a REST API for querying and controlling VPN state.

### Configuration

```ini
HTTP_API_ENABLED=true
HTTP_API_PORT=8080
HTTP_API_BIND=127.0.0.1
HTTP_API_KEY=your_api_key_here

# Auth policy. Tri-state: true | false | auto (default auto).
#   auto:  require HTTP_API_KEY whenever the API is bound to a non-loopback
#          address. Loopback-only binds without a key are allowed.
#   true:  always require a key, even on loopback.
#   false: never require a key (legacy unauthenticated mode — foot-gun if
#          you bind non-loopback; logs a warning in that case).
# When the policy resolves to "required" and HTTP_API_KEY is empty, mole
# refuses to start (`mole run` exits non-zero) rather than silently spawn an
# unauthenticated API server. Generate a key with `sudo mole api-key generate`.
# HTTP_API_REQUIRE_AUTH=auto
```

> **Migration note:** prior versions warned but still served. From this
> release onward, the default policy refuses to start when bound non-loopback
> without a key. If you have a deployment that intentionally exposes the API
> without authentication, set `HTTP_API_REQUIRE_AUTH=false` to opt out (a
> warning is still logged).

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/status` | VPN connection status |
| GET | `/v1/port` | Current forwarded port |
| GET | `/v1/ip` | Public IP address |
| GET | `/v1/server` | Current server info |
| GET | `/v1/health` | Health check status |
| GET | `/v1/dns` | DoT resolver state: cache, blocklist, per-upstream pool stats, counters, latency percentiles |
| GET | `/metrics` | Prometheus exposition format — same data as `/v1/dns` + `/v1/status`, re-shaped for time-series scraping |
| PUT | `/v1/vpn/restart` | Trigger reconnection |

### Prometheus metrics

`GET /metrics` returns Prometheus text exposition format. The endpoint goes
through the same auth path as the rest of the API, so set `HTTP_API_KEY`
and configure your Prometheus scrape with bearer-token auth.

Sample output excerpt:

```
# HELP mole_vpn_connected 1 if the WireGuard tunnel is currently up, 0 otherwise.
# TYPE mole_vpn_connected gauge
mole_vpn_connected 1

# HELP mole_dns_queries_total Total DNS queries received by the resolver.
# TYPE mole_dns_queries_total counter
mole_dns_queries_total 40

# HELP mole_dns_upstream_query_latency_p50_seconds Per-upstream DoT query latency P50 over the rolling window (seconds).
# TYPE mole_dns_upstream_query_latency_p50_seconds gauge
mole_dns_upstream_query_latency_p50_seconds{upstream="cloudflare"} 0.0548
```

Top-level metrics include `mole_vpn_connected`, `mole_vpn_forwarded_port`,
`mole_dns_queries_total`, `mole_dns_cache_hits_total`,
`mole_dns_cache_misses_total`, `mole_dns_blocked_total`,
`mole_dns_resolve_errors_total`, `mole_dns_in_flight_peak`,
`mole_dns_cache_entries`, `mole_dns_blocked_domains`,
`mole_dns_blocklist_last_update_seconds`,
`mole_dns_blocklist_update_last_duration_seconds`,
`mole_dns_blocklist_update_failures_total`,
plus `mole_build_info{version}`.

Per-upstream DNS metrics carry an `upstream` label and include
`queries_total`, `errors_total`, `retries_total`, `failovers_total`,
`open_connections`, `pool_size`, `query_latency_p{50,95,99}_seconds`,
and `query_latency_samples`.

VPN-tunnel observability:

- `mole_vpn_handshake_age_seconds` (gauge) — seconds since the last
  WireGuard handshake. A "connected" tunnel with a stale handshake is a
  real silent-failure mode. Alert on `> 300`.
- `mole_vpn_endpoint_info{server, country, endpoint_ip}` (gauge=1) —
  current endpoint identity as labels. Joinable in PromQL with
  `mole_vpn_connected` for "is this server, in this country, up?"
- `mole_vpn_renewals_total{result="success|failure"}` (counter) — every
  full renewal attempt logged here. The configured renewal cadence
  (`RENEWAL_INTERVAL`, default 7 days) appears as a stair-step on success;
  rising failure ratio is alertable.
- `mole_vpn_renewal_last_duration_seconds` (gauge) — wall-clock duration
  of the most recent renewal.
- `mole_vpn_renewal_last_success_timestamp_seconds` (gauge) — Unix ts of
  the most recent successful renewal. Alert on
  `time() - this > 2 * RENEWAL_INTERVAL` (so a single missed renewal
  doesn't fire, but a stuck-down state does).
- `mole_vpn_port_forward_age_seconds` (gauge) — seconds since the last
  successful NAT-PMP keepalive. Catches silent-stale port forwards.
- `mole_vpn_port_forward_renewals_total{result}` (counter).

Example Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: 'mole'
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets: ['mole.internal:8080']
    authorization:
      type: Bearer
      credentials: 'YOUR_HTTP_API_KEY'
```

A ready-to-use Grafana dashboard and Prometheus alert rules ship in
[`examples/`](examples/) — drop them into your provisioning paths to get
a 22-panel dashboard plus 10 alert rules covering tunnel health, DNS
performance, errors, and blocklist freshness.

### `/v1/dns` response shape

```json
{
  "enabled": true,
  "upstream": "cloudflare",
  "upstreams": [
    {
      "name": "cloudflare",
      "host": "1.1.1.1",
      "port": 853,
      "pool_size": 2,
      "open_connections": 2,
      "primary": true,
      "query_p50_ms": 12.4,
      "query_p95_ms": 28.1,
      "query_p99_ms": 45.7,
      "query_samples": 1024,
      "counters": {
        "queries": 5234,
        "errors": 3,
        "retries": 1,
        "failovers_out": 0
      }
    }
  ],
  "caching": true,
  "cache_entries": 412,
  "cache_size_bytes": 38291,
  "blocked_domains": 97057,
  "in_flight": 0,
  "counters": {
    "queries_total": 8421,
    "cache_hits": 3187,
    "cache_misses": 5234,
    "in_flight_peak": 14,
    "singleflight_collapses": 1842,
    "blocked": 0,
    "upstream_queries": 5234,
    "upstream_errors": 3,
    "retries": 1,
    "failovers": 0,
    "resolve_errors": 0
  },
  "last_blocklist_update": 1776740747,
  "block_ads": true,
  "block_malware": true,
  "block_tracking": false
}
```

| Field | Meaning |
|---|---|
| `upstreams[]` | One entry per configured DoT target. The first is the primary; others are failover targets tried in order. |
| `upstreams[].open_connections` | TLS connections currently open to this upstream. Oscillates `0..pool_size` with traffic — idle connections are closed by remote and reopened lazily. |
| `upstreams[].query_p{50,95,99}_ms` | Latency percentiles (nearest-rank, no interpolation) over the rolling 1024-sample window of *successful* upstream queries against this target. Failures excluded so timeouts don't drag percentiles toward `DOT_QUERY_TIMEOUT`. |
| `upstreams[].query_samples` | Number of samples backing the percentiles above. |
| `upstreams[].counters.queries` | Attempts (success + fail) against this upstream. |
| `upstreams[].counters.errors` | Failed attempts against this upstream. |
| `upstreams[].counters.retries` | Same-upstream retries on this target (only when `DOT_QUERY_RETRIES > 0`). |
| `upstreams[].counters.failovers_out` | Times we gave up on THIS upstream and moved to the next in the list. Always 0 for the last upstream. |
| `in_flight` | Resolves currently in flight (waiting on upstream or singleflight leader). |
| `cache_entries` | Number of cached responses. |
| `cache_size_bytes` | Total bytes of cached response data. |
| `counters.queries_total` | Every incoming query to the resolver. |
| `counters.cache_hits` | Resolves served from cache. |
| `counters.cache_misses` | Resolves that didn't find a cache entry (includes singleflight followers). |
| `counters.singleflight_collapses` | Concurrent identical queries that piggy-backed on an in-flight upstream call instead of issuing their own. Sustained-high value on a single client = real workload dedup; near-zero with high `cache_misses` = mostly distinct names. |
| `counters.upstream_queries` | Total upstream attempts. Equals the sum of `upstreams[].counters.queries`. |
| `counters.upstream_errors` | Total upstream failures. Equals the sum of `upstreams[].counters.errors`. |
| `counters.retries` | Total same-upstream retries across all targets. |
| `counters.failovers` | Total cross-upstream failovers across all targets. |
| `counters.resolve_errors` | Resolves that returned no answer to the client (every upstream failed). This is the client-visible failure count. |
| `last_blocklist_update` | Unix epoch seconds of the last successful blocklist refresh, or `null` if none yet. |

## Troubleshooting

### ProtonVPN rate limiting
If you see "Rate limited, will retry with backoff", MOLE will automatically retry with exponential backoff (5s, 10s, 20s).

### PIA rate limiting
PIA has stricter rate limits. MOLE will retry with longer delays (30s, 60s, 120s). If persistent, wait 15+ minutes before trying again.

### Port forwarding not working
- **PIA**: Ensure your region supports port forwarding (`mole regions pia --pf`)
- **ProtonVPN**: Requires Plus plan and `natpmpc` installed

### VPN not connecting
1. Check logs: `sudo mole logs -f`
2. Validate config: `mole validate`
3. Try a different server/region

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or pull request.
