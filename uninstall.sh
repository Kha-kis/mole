#!/bin/bash
#
# MOLE Uninstall Script
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}MOLE Uninstaller${NC}"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo ./uninstall.sh)${NC}"
    exit 1
fi

read -p "This will remove MOLE. Continue? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 1
fi

echo ""
echo "Stopping and disabling services..."

# Stop qbittorrent passthrough first if it exists
if [ -f /etc/systemd/system/qbittorrent-passthrough.service ]; then
    echo "  Stopping qbittorrent-passthrough..."
    systemctl stop qbittorrent-passthrough 2>/dev/null || true
    systemctl disable qbittorrent-passthrough 2>/dev/null || true
fi

# Stop qbittorrent-mole if it exists (depends on mole)
if [ -f /etc/systemd/system/qbittorrent-mole.service ]; then
    echo "  Stopping qbittorrent-mole..."
    systemctl stop qbittorrent-mole 2>/dev/null || true
    systemctl disable qbittorrent-mole 2>/dev/null || true
fi

# Stop mole service
echo "  Stopping mole..."
systemctl stop mole 2>/dev/null || true
systemctl disable mole 2>/dev/null || true

echo "Removing files..."
rm -f /usr/local/bin/mole
rm -rf /usr/local/lib/mole
rm -f /etc/systemd/system/mole.service
rm -f /etc/systemd/system/qbittorrent-mole.service
rm -f /etc/systemd/system/qbittorrent-passthrough.service
systemctl daemon-reload

read -p "Remove configuration and state? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /etc/mole
    rm -rf /var/lib/mole
    rm -f /etc/wireguard/mole.conf
    echo "Configuration removed."
else
    echo "Configuration preserved in /etc/mole"
fi

echo ""
echo -e "${GREEN}MOLE uninstalled.${NC}"
echo ""
echo "Note: Network namespace 'vpn' and veth interfaces were not removed."
echo "To remove manually:"
echo "  sudo ip link del veth-host"
echo "  sudo ip netns del vpn"
