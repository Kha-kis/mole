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

# Check for package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
else
    PKG_MANAGER="unknown"
fi

# ═══════════════════════════════════════════════════════════════════
# Install system dependencies
# ═══════════════════════════════════════════════════════════════════
echo "Checking system dependencies..."

install_package() {
    local pkg=$1
    local apt_pkg=${2:-$1}

    if ! command -v "$pkg" &> /dev/null; then
        echo -n "  Installing $apt_pkg... "
        case $PKG_MANAGER in
            apt)
                apt-get install -y "$apt_pkg" > /dev/null 2>&1
                ;;
            dnf|yum)
                $PKG_MANAGER install -y "$apt_pkg" > /dev/null 2>&1
                ;;
            pacman)
                pacman -S --noconfirm "$apt_pkg" > /dev/null 2>&1
                ;;
            *)
                echo -e "${YELLOW}skipped (install manually)${NC}"
                return 1
                ;;
        esac
        echo -e "${GREEN}done${NC}"
    else
        echo -e "  $pkg: ${GREEN}installed${NC}"
    fi
}

# Update package lists (apt only)
if [ "$PKG_MANAGER" = "apt" ]; then
    echo -n "  Updating package lists... "
    apt-get update > /dev/null 2>&1
    echo -e "${GREEN}done${NC}"
fi

# Required dependencies
install_package "wg" "wireguard-tools"
install_package "curl" "curl"
install_package "ip" "iproute2"
install_package "iptables" "iptables"
install_package "python3" "python3"
install_package "pip3" "python3-pip"

# Optional dependencies
echo ""
echo "Optional dependencies:"

# natpmpc for ProtonVPN port forwarding
if ! command -v natpmpc &> /dev/null; then
    echo -n "  natpmpc (ProtonVPN port forwarding)... "
    case $PKG_MANAGER in
        apt)
            apt-get install -y natpmpc > /dev/null 2>&1 && echo -e "${GREEN}installed${NC}" || echo -e "${YELLOW}failed${NC}"
            ;;
        *)
            echo -e "${YELLOW}skipped (install manually)${NC}"
            ;;
    esac
else
    echo -e "  natpmpc: ${GREEN}installed${NC}"
fi

# qbittorrent-nox
if ! command -v qbittorrent-nox &> /dev/null; then
    echo -e "  qbittorrent-nox: ${YELLOW}not installed${NC} (optional, for torrent integration)"
    echo -e "    Install with: sudo apt install qbittorrent-nox"
else
    echo -e "  qbittorrent-nox: ${GREEN}installed${NC}"
fi

# proton-client Python package
if python3 -c "import proton" 2>/dev/null; then
    echo -e "  proton-client: ${GREEN}installed${NC}"
else
    echo -n "  proton-client (ProtonVPN)... "
    pip3 install proton-client > /dev/null 2>&1 && echo -e "${GREEN}installed${NC}" || echo -e "${YELLOW}failed (install with: pip3 install proton-client)${NC}"
fi

# ═══════════════════════════════════════════════════════════════════
# Install MOLE
# ═══════════════════════════════════════════════════════════════════
echo ""
echo "Installing MOLE..."

# Install Python package
echo -n "  Installing mole_pkg to /usr/local/lib/mole... "
mkdir -p /usr/local/lib/mole
cp -r "$SCRIPT_DIR/mole_pkg" /usr/local/lib/mole/
echo -e "${GREEN}done${NC}"

# Create wrapper script
echo -n "  Installing /usr/local/bin/mole... "
cat > /usr/local/bin/mole << 'EOF'
#!/usr/bin/env python3
import sys
sys.path.insert(0, '/usr/local/lib/mole')
from mole_pkg.cli import main
sys.exit(main())
EOF
chmod 755 /usr/local/bin/mole
echo -e "${GREEN}done${NC}"

# Install systemd service
echo -n "  Installing systemd service... "
cp "$SCRIPT_DIR/mole.service" /etc/systemd/system/mole.service
systemctl daemon-reload
echo -e "${GREEN}done${NC}"

# Enable service (but don't start yet)
echo -n "  Enabling mole service... "
systemctl enable mole >/dev/null 2>&1
echo -e "${GREEN}done${NC}"

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""

# Run interactive setup
/usr/local/bin/mole init
