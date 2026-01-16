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

# ProtonVPN NAT-PMP requires more frequent refresh
KEEPALIVE_INTERVAL=45
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

### Configuration

```ini
DOT_ENABLED=true
DOT_UPSTREAM=cloudflare  # cloudflare, cloudflare-family, quad9, google, custom

# Filtering
DOT_BLOCK_ADS=true
DOT_BLOCK_MALWARE=true

# Caching
DOT_CACHING=true
DOT_UPDATE_PERIOD=24h
```

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
```

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/status` | VPN connection status |
| GET | `/v1/port` | Current forwarded port |
| GET | `/v1/ip` | Public IP address |
| GET | `/v1/server` | Current server info |
| GET | `/v1/health` | Health check status |
| GET | `/v1/dns` | DNS cache and blocklist stats |
| PUT | `/v1/vpn/restart` | Trigger reconnection |

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
