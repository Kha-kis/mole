#!/bin/bash
#
# MOLE Installation Script
# Managed Obfuscated Link Environment
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║  MOLE - Managed Obfuscated Link Environment                   ║"
echo "║  Installation Script                                          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Please run as root (sudo ./install.sh)${NC}"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing MOLE..."

# Install binary
echo -n "  Installing /usr/local/bin/mole... "
cp "$SCRIPT_DIR/mole" /usr/local/bin/mole
chmod 755 /usr/local/bin/mole
echo -e "${GREEN}done${NC}"

# Install systemd service
echo -n "  Installing systemd service... "
cp "$SCRIPT_DIR/mole.service" /etc/systemd/system/mole.service
systemctl daemon-reload
echo -e "${GREEN}done${NC}"

# Run init
echo ""
echo "Running mole init..."
echo ""
/usr/local/bin/mole init

# Enable service (but don't start)
echo ""
echo -n "Enabling mole service... "
systemctl enable mole >/dev/null 2>&1
echo -e "${GREEN}done${NC}"

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/mole/config with your VPN credentials"
echo "  2. Start the service: sudo systemctl start mole"
echo "  3. Check status: sudo mole status"
echo ""
echo "Optional - Setup qBittorrent in VPN namespace:"
echo "  sudo mole qbittorrent setup"
echo ""
