# MOLE - Managed Obfuscated Link Environment

A VPN tunnel manager with automatic port forwarding and torrent client integration.

MOLE runs your VPN connection in an isolated network namespace, automatically handles token renewal, port forwarding keepalive, and updates your torrent client's listening port.

## Features

- **Network Namespace Isolation** - VPN traffic is isolated from host network
- **Kill Switch** - Blocks all traffic if VPN connection drops
- **DNS Leak Protection** - DNS queries route through VPN only
- **Automatic Token Renewal** - Refreshes VPN credentials before expiration
- **Port Forwarding** - Automatically requests and maintains forwarded ports
- **Torrent Client Integration** - Updates qBittorrent's listening port via API
- **Health Monitoring** - Watchdog detects and recovers from connection failures
- **Systemd Integration** - Runs as a proper system service
- **Config Validation** - Check configuration for errors before running
- **Speed Testing** - Test VPN connection speed
- **Region Auto-Select** - Find the fastest region with port forwarding support
- **Bandwidth Statistics** - Track upload/download usage over time

## Supported Providers

- **PIA (Private Internet Access)** - Full support with port forwarding

## Supported Torrent Clients

- **qBittorrent** - Via Web API

## Requirements

- Linux with network namespace support
- WireGuard (`wireguard-tools`)
- Python 3.8+
- curl
- Root access (for network namespace management)

## Installation

```bash
git clone https://github.com/yourusername/mole.git
cd mole
sudo ./install.sh
```

The installer will:
- Install the `mole` command to `/usr/local/bin/`
- Install the systemd service
- Run `mole init` to create config directories
- Enable the service (but not start it)

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

Edit `/etc/mole/config` with your VPN credentials (see `config.example` for all options):

```ini
# VPN Provider
VPN_PROVIDER=pia

# PIA Credentials
PIA_USER=your_username
PIA_PASS=your_password
PIA_REGION=ca_toronto

# Network Namespace
NETNS_NAME=vpn
VETH_HOST_IP=10.200.200.1
VETH_VPN_IP=10.200.200.2

# Host network interface (for NAT)
HOST_INTERFACE=eth0

# Port Forwarding (set to false to disable)
PORT_FORWARD=true

# Torrent Client (qbittorrent or none)
TORRENT_CLIENT=qbittorrent
QB_API_URL=http://localhost:8080/api/v2/app

# Timing (seconds)
RENEWAL_INTERVAL=72000    # 20 hours
KEEPALIVE_INTERVAL=900    # 15 minutes
WATCHDOG_INTERVAL=60      # 1 minute
WATCHDOG_MAX_FAILURES=3
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

### Commands

```
mole --version       Show version
mole validate        Validate configuration file
mole ip              Show current public IP through VPN
mole regions [provider] [--pf]  List VPN regions (--pf for port forwarding only)
mole autoselect      Find fastest region with port forwarding
mole speedtest       Test VPN connection speed
mole stats [--save]  Show bandwidth statistics
sudo mole init       Initialize directory structure
sudo mole status     Show VPN connection status
sudo mole qbittorrent setup    Setup qBittorrent in VPN namespace
sudo mole qbittorrent start    Start qBittorrent service
sudo mole qbittorrent stop     Stop qBittorrent service
mole qbittorrent status        Check qBittorrent status
sudo mole restart    Force VPN reconnection
sudo mole stop       Stop the VPN service
sudo mole logs       Show service logs (use -f to follow)
sudo mole run        Run the VPN manager (used by systemd)
```

## Directory Structure

```
/etc/mole/
  config              Configuration file
  providers/
    pia-ca.crt        PIA CA certificate

/var/lib/mole/        Runtime state files

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

### Setup Options

```bash
sudo mole qbittorrent setup --user myuser --port 8080
```

- `--user`: User to run qBittorrent as (auto-detected if not specified)
- `--port`: Web UI port (default: 8080)

## Running Other Applications Through VPN

To run any application through the VPN namespace:

```bash
sudo ip netns exec vpn <command>
```

## Accessing Services in the Namespace

Services running in the VPN namespace can be accessed from the host via the veth IP (default: 10.200.200.2).

For localhost access, you can use socat:

```bash
socat TCP-LISTEN:8080,bind=127.0.0.1,fork,reuseaddr TCP:10.200.200.2:8080
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

This means if the VPN drops:
- Torrent traffic stops immediately (no IP leak)
- qBittorrent web UI remains accessible from your host
- The watchdog will detect the failure and reconnect

### DNS Leak Protection

DNS queries from applications in the namespace are forced through the VPN tunnel. The `mole status` command includes a DNS leak check that verifies your DNS requests are resolving through the VPN server IP, not your ISP.

### Network Isolation

The VPN runs in a separate network namespace, completely isolated from your host's network stack. Applications must be explicitly run inside the namespace to use the VPN. Your host's regular internet traffic is unaffected.

## Utility Commands

### Config Validation

Before starting MOLE, validate your configuration:

```bash
mole validate
```

This checks for missing credentials, invalid settings, and common configuration errors.

### Region Selection

List all available regions:

```bash
mole regions pia           # All PIA regions
mole regions pia --pf      # Only regions with port forwarding
```

Find the fastest region automatically:

```bash
mole autoselect
```

This tests latency to all port-forwarding regions and recommends the fastest one.

### Speed Testing

Test your VPN connection speed:

```bash
mole speedtest
```

### Bandwidth Statistics

View current and historical bandwidth usage:

```bash
mole stats           # View stats
mole stats --save    # Save current session to history
```

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or pull request.
