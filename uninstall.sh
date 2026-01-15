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
echo "Stopping and disabling service..."
systemctl stop mole 2>/dev/null || true
systemctl disable mole 2>/dev/null || true

echo "Removing files..."
rm -f /usr/local/bin/mole
rm -f /etc/systemd/system/mole.service
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
