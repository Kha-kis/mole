# MOLE - Managed Obfuscated Link Environment

A VPN tunnel manager with automatic port forwarding and torrent client integration.

MOLE runs your VPN connection in an isolated network namespace, automatically handles token renewal, port forwarding keepalive, and updates your torrent client's listening port.

## Features

- **Network Namespace Isolation** - VPN traffic is isolated from host network
- **Automatic Token Renewal** - Refreshes VPN credentials before expiration
- **Port Forwarding** - Automatically requests and maintains forwarded ports
- **Torrent Client Integration** - Updates qBittorrent's listening port via API
- **Health Monitoring** - Watchdog detects and recovers from connection failures
- **Systemd Integration** - Runs as a proper system service

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
git clone https://gitea.okami.icu/khak1s/mole.git
cd mole
sudo ./install.sh
```

The install script performs the following:
- Installs the `mole` binary to `/usr/local/bin/mole`
- Installs the systemd service to `/etc/systemd/system/mole.service`
- Runs `mole init` to create the directory structure (`/etc/mole/`, `/var/lib/mole/`)
- Enables the service (but does not start it)

## Uninstallation

To remove MOLE from your system:

```bash
sudo ./uninstall.sh
```

The uninstall script will:
- Stop and disable the mole service
- Remove `/usr/local/bin/mole`
- Remove the systemd service file
- Optionally remove configuration and state files (`/etc/mole/`, `/var/lib/mole/`, `/etc/wireguard/mole.conf`)

**Note:** The network namespace and veth interfaces are not automatically removed. To clean them up manually:

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

# Torrent Client
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
sudo journalctl -u mole -f
```

### Commands

```
mole --version     Show version
sudo mole init     Initialize directory structure
sudo mole status   Show VPN connection status
sudo mole run      Run the VPN manager (used by systemd)
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

## Running Applications Through VPN

To run an application through the VPN namespace:

```bash
sudo ip netns exec vpn <command>
```

For example, running qBittorrent in the VPN namespace:

```bash
sudo ip netns exec vpn sudo -u youruser qbittorrent-nox --webui-port=8080
```

## Accessing Services in the Namespace

Services running in the VPN namespace can be accessed from the host via the veth IP (default: 10.200.200.2).

For localhost access, you can use socat:

```bash
socat TCP-LISTEN:8080,bind=127.0.0.1,fork,reuseaddr TCP:10.200.200.2:8080
```

## License

MIT License

## Contributing

Contributions welcome! Please open an issue or pull request.
