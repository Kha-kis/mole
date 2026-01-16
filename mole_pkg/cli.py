#!/usr/bin/env python3
"""
MOLE CLI - Command Line Interface
"""

import argparse
import asyncio
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__
from .config import Config, validate_config
from .constants import (
    DEFAULT_CONFIG_FILE,
    DEFAULT_CONFIG_DIR,
    DEFAULT_STATE_DIR,
    PIA_CA_CERT,
)
from .utils import (
    log,
    run_cmd,
    run_in_netns,
    secure_write_file,
    setup_logging,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════

def _fetch_pia_regions() -> List[Dict]:
    """Fetch PIA regions from API"""
    with urllib.request.urlopen(
        "https://serverlist.piaservers.net/vpninfo/servers/v6",
        timeout=30
    ) as resp:
        data = resp.readline().decode()
        servers = json.loads(data)

    regions = []
    for region in servers.get("regions", []):
        if region.get("servers", {}).get("wg"):
            regions.append({
                "id": region["id"],
                "name": region["name"],
                "port_forward": region.get("port_forward", False),
                "servers": region.get("servers", {}).get("wg", [])
            })
    return regions


def _fetch_proton_servers(tier: int = 2) -> List[Dict]:
    """Fetch ProtonVPN servers using authenticated session.

    ProtonVPN requires authentication to fetch the server list.
    This function tries to use an existing session from /var/lib/mole/proton_session.json.

    Args:
        tier: User tier (0=free, 1=basic, 2=plus). Filters servers by tier.

    Returns:
        List of server dicts with: name, hostname, country, city, load,
        tier, features, entry_ip, has_p2p
    """
    session_file = Path(DEFAULT_STATE_DIR) / "proton_session.json"

    if not session_file.exists():
        raise Exception(
            "ProtonVPN requires authentication to list servers.\n"
            "Run 'sudo mole init' to set up ProtonVPN first, or start the service\n"
            "with 'sudo systemctl start mole' to create a session."
        )

    # Load session and make authenticated request
    try:
        from proton import Session as ProtonAPISession

        dump = json.loads(session_file.read_text())
        session = ProtonAPISession.load(dump, TLSPinning=False, timeout=30)

        # Try to refresh the session and save it
        try:
            session.refresh()
            # Save refreshed session
            new_dump = session.dump()
            if isinstance(new_dump, dict):
                new_dump = json.dumps(new_dump)
            session_file.write_text(new_dump)
        except Exception:
            pass  # May fail if already valid

        response = session.api_request("/vpn/logicals")

        if response.get("Code") != 1000:
            raise Exception(f"API error: {response.get('Error', 'Unknown error')}")

        data = response

    except ImportError:
        raise Exception(
            "proton-client package not installed.\n"
            "Install with: pip3 install proton-client"
        )
    except Exception as e:
        if "proton_session" in str(e).lower() or "session" in str(e).lower():
            raise Exception(
                "ProtonVPN session expired or invalid.\n"
                "Start the service with 'sudo systemctl start mole' to refresh."
            )
        raise

    servers = []
    for server in data.get("LogicalServers", []):
        # Skip disabled servers
        if server.get("Status") == 0:
            continue

        # Skip servers above user's tier
        if server.get("Tier", 0) > tier:
            continue

        # Get WireGuard server info
        server_list = server.get("Servers", [])
        entry_ip = None
        for s in server_list:
            if s.get("X25519PublicKey"):
                entry_ip = s.get("EntryIP")
                break

        if not entry_ip:
            continue

        features = server.get("Features", 0)
        has_p2p = bool(features & 4)  # Feature bit 4 = P2P

        servers.append({
            "name": server.get("Name"),
            "hostname": server.get("Domain"),
            "country": server.get("ExitCountry"),
            "city": server.get("City", ""),
            "load": server.get("Load", 0),
            "tier": server.get("Tier", 0),
            "features": features,
            "entry_ip": entry_ip,
            "has_p2p": has_p2p,
        })

    return servers


def _get_proton_countries(servers: List[Dict]) -> Dict[str, Dict]:
    """Group ProtonVPN servers by country.

    Returns:
        Dict mapping country code to {name, servers, has_p2p}
    """
    # Country code to name mapping (common ones)
    country_names = {
        "US": "United States", "GB": "United Kingdom", "CA": "Canada",
        "AU": "Australia", "DE": "Germany", "FR": "France", "NL": "Netherlands",
        "CH": "Switzerland", "SE": "Sweden", "NO": "Norway", "DK": "Denmark",
        "FI": "Finland", "AT": "Austria", "BE": "Belgium", "CZ": "Czech Republic",
        "ES": "Spain", "IT": "Italy", "PL": "Poland", "JP": "Japan",
        "SG": "Singapore", "HK": "Hong Kong", "BR": "Brazil", "MX": "Mexico",
        "AR": "Argentina", "ZA": "South Africa", "IN": "India", "KR": "South Korea",
        "IE": "Ireland", "PT": "Portugal", "RO": "Romania", "HU": "Hungary",
        "IS": "Iceland", "NZ": "New Zealand", "LU": "Luxembourg",
    }

    countries = {}
    for server in servers:
        cc = server["country"]
        if cc not in countries:
            countries[cc] = {
                "code": cc,
                "name": country_names.get(cc, cc),
                "servers": [],
                "has_p2p": False,
            }
        countries[cc]["servers"].append(server)
        if server["has_p2p"]:
            countries[cc]["has_p2p"] = True

    return countries


def _ping_server(server_ip: str, netns: str = None) -> Optional[float]:
    """Ping a server and return latency in ms, or None if failed"""
    try:
        if netns:
            result = run_in_netns(["ping", "-c", "1", "-W", "2", server_ip], netns, check=False)
        else:
            result = run_cmd(["ping", "-c", "1", "-W", "2", server_ip], check=False)

        if result.returncode == 0:
            for part in result.stdout.split():
                if part.startswith("time="):
                    return float(part[5:])
    except Exception:
        pass
    return None


def _apply_region_to_config(region: str, server: str = None) -> bool:
    """Apply region (and optionally server) selection to config file"""

    try:
        with open(DEFAULT_CONFIG_FILE, 'r') as f:
            config_content = f.read()

        # Update or add PIA_REGION
        if re.search(r'^PIA_REGION=', config_content, re.MULTILINE):
            config_content = re.sub(
                r'^PIA_REGION=.*$',
                f'PIA_REGION={region}',
                config_content,
                flags=re.MULTILINE
            )
        else:
            if not config_content.endswith('\n'):
                config_content += '\n'
            config_content += f'\nPIA_REGION={region}\n'

        # Update or add/remove PIA_SERVER
        if server:
            if re.search(r'^PIA_SERVER=', config_content, re.MULTILINE):
                config_content = re.sub(
                    r'^PIA_SERVER=.*$',
                    f'PIA_SERVER={server}',
                    config_content,
                    flags=re.MULTILINE
                )
            elif re.search(r'^#\s*PIA_SERVER=', config_content, re.MULTILINE):
                config_content = re.sub(
                    r'^#\s*PIA_SERVER=.*$',
                    f'PIA_SERVER={server}',
                    config_content,
                    flags=re.MULTILINE
                )
            else:
                config_content = re.sub(
                    r'^(PIA_REGION=.*)$',
                    f'\\1\nPIA_SERVER={server}',
                    config_content,
                    flags=re.MULTILINE
                )
        else:
            if re.search(r'^PIA_SERVER=', config_content, re.MULTILINE):
                config_content = re.sub(
                    r'^PIA_SERVER=(.*)$',
                    r'# PIA_SERVER=\1',
                    config_content,
                    flags=re.MULTILINE
                )

        with open(DEFAULT_CONFIG_FILE, 'w') as f:
            f.write(config_content)

        if server:
            print(f"\nConfig updated:")
            print(f"  PIA_REGION={region}")
            print(f"  PIA_SERVER={server}")
        else:
            print(f"\nConfig updated: PIA_REGION={region}")

        print("Restart MOLE for changes to take effect: sudo systemctl restart mole")
        return True

    except PermissionError:
        print(f"\nError: Permission denied writing to {DEFAULT_CONFIG_FILE}")
        print("Run with sudo to update config, or add manually:")
        print(f"  PIA_REGION={region}")
        if server:
            print(f"  PIA_SERVER={server}")
        return False
    except Exception as e:
        print(f"\nError updating config: {e}")
        return False


def _apply_proton_config(country: str, server: str = None) -> bool:
    """Apply ProtonVPN country (and optionally server) selection to config file"""

    try:
        with open(DEFAULT_CONFIG_FILE, 'r') as f:
            config_content = f.read()

        # Update or add PROTON_COUNTRY
        if re.search(r'^PROTON_COUNTRY=', config_content, re.MULTILINE):
            config_content = re.sub(
                r'^PROTON_COUNTRY=.*$',
                f'PROTON_COUNTRY={country}',
                config_content,
                flags=re.MULTILINE
            )
        elif re.search(r'^#\s*PROTON_COUNTRY=', config_content, re.MULTILINE):
            config_content = re.sub(
                r'^#\s*PROTON_COUNTRY=.*$',
                f'PROTON_COUNTRY={country}',
                config_content,
                flags=re.MULTILINE
            )
        else:
            if not config_content.endswith('\n'):
                config_content += '\n'
            config_content += f'\nPROTON_COUNTRY={country}\n'

        # Update or add/remove PROTON_SERVER
        if server:
            if re.search(r'^PROTON_SERVER=', config_content, re.MULTILINE):
                config_content = re.sub(
                    r'^PROTON_SERVER=.*$',
                    f'PROTON_SERVER={server}',
                    config_content,
                    flags=re.MULTILINE
                )
            elif re.search(r'^#\s*PROTON_SERVER=', config_content, re.MULTILINE):
                config_content = re.sub(
                    r'^#\s*PROTON_SERVER=.*$',
                    f'PROTON_SERVER={server}',
                    config_content,
                    flags=re.MULTILINE
                )
            else:
                config_content = re.sub(
                    r'^(PROTON_COUNTRY=.*)$',
                    f'\\1\nPROTON_SERVER={server}',
                    config_content,
                    flags=re.MULTILINE
                )
        else:
            if re.search(r'^PROTON_SERVER=', config_content, re.MULTILINE):
                config_content = re.sub(
                    r'^PROTON_SERVER=(.*)$',
                    r'# PROTON_SERVER=\1',
                    config_content,
                    flags=re.MULTILINE
                )

        with open(DEFAULT_CONFIG_FILE, 'w') as f:
            f.write(config_content)

        if server:
            print(f"\nConfig updated:")
            print(f"  PROTON_COUNTRY={country}")
            print(f"  PROTON_SERVER={server}")
        else:
            print(f"\nConfig updated: PROTON_COUNTRY={country}")

        print("Restart MOLE for changes to take effect: sudo systemctl restart mole")
        return True

    except PermissionError:
        print(f"\nError: Permission denied writing to {DEFAULT_CONFIG_FILE}")
        print("Run with sudo to update config, or add manually:")
        print(f"  PROTON_COUNTRY={country}")
        if server:
            print(f"  PROTON_SERVER={server}")
        return False
    except Exception as e:
        print(f"\nError updating config: {e}")
        return False


def _qbittorrent_setup_services(enable_passthrough: bool = False, verbose: bool = True) -> bool:
    """Setup qBittorrent wrapper scripts and systemd service files.

    Creates wrapper scripts that read config at runtime, so service files
    never need to be regenerated when config changes.
    """
    lib_dir = Path("/usr/local/lib/mole")
    lib_dir.mkdir(parents=True, exist_ok=True)

    # Create main qBittorrent wrapper script
    # This reads config at runtime so changes take effect on restart
    qb_wrapper = lib_dir / "qbittorrent-wrapper.sh"
    qb_wrapper_content = '''#!/bin/bash
# qBittorrent wrapper - reads config at runtime
set -e

CONFIG_FILE="${MOLE_CONFIG:-/etc/mole/config}"

if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

NETNS="${NETNS_NAME:-vpn}"
QB_USER_RUN="${QB_USER:-nobody}"
QB_PORT_RUN="${QB_PORT:-8080}"

# Wait for VPN interface to be up (max 30 seconds)
for i in {1..30}; do
    if ip netns exec "$NETNS" ip link show mole >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Run qBittorrent in the VPN namespace
exec /usr/bin/ip netns exec "$NETNS" sudo -u "$QB_USER_RUN" /usr/bin/qbittorrent-nox --webui-port="$QB_PORT_RUN"
'''
    qb_wrapper.write_text(qb_wrapper_content)
    qb_wrapper.chmod(0o755)
    if verbose:
        print(f"  Created: {qb_wrapper}")

    # Create passthrough wrapper script
    pt_wrapper = lib_dir / "qbittorrent-passthrough.sh"
    pt_wrapper_content = '''#!/bin/bash
# qBittorrent passthrough wrapper - reads config at runtime
set -e

CONFIG_FILE="${MOLE_CONFIG:-/etc/mole/config}"

if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

QB_PORT_RUN="${QB_PORT:-8080}"
VETH_VPN_IP_RUN="${VETH_VPN_IP:-10.200.200.2}"

# Forward localhost:port to VPN namespace
exec /usr/bin/socat TCP-LISTEN:"$QB_PORT_RUN",bind=127.0.0.1,fork,reuseaddr TCP:"$VETH_VPN_IP_RUN":"$QB_PORT_RUN"
'''
    pt_wrapper.write_text(pt_wrapper_content)
    pt_wrapper.chmod(0o755)
    if verbose:
        print(f"  Created: {pt_wrapper}")

    # Create static systemd service for qBittorrent
    # This never needs to change - wrapper reads config at runtime
    qb_service = Path("/etc/systemd/system/qbittorrent-mole.service")
    qb_service_content = """[Unit]
Description=qBittorrent-nox in MOLE VPN namespace
After=network.target mole.service
Wants=mole.service

[Service]
Type=simple
ExecStart=/usr/local/lib/mole/qbittorrent-wrapper.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
    qb_service.write_text(qb_service_content)
    if verbose:
        print(f"  Created: {qb_service}")

    # Create passthrough service if requested
    if enable_passthrough:
        result = subprocess.run(["which", "socat"], capture_output=True)
        if result.returncode != 0:
            if verbose:
                print("  Warning: socat not installed, skipping passthrough service")
        else:
            pt_service = Path("/etc/systemd/system/qbittorrent-passthrough.service")
            pt_service_content = """[Unit]
Description=qBittorrent localhost passthrough
After=qbittorrent-mole.service
BindsTo=qbittorrent-mole.service

[Service]
Type=simple
ExecStart=/usr/local/lib/mole/qbittorrent-passthrough.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
            pt_service.write_text(pt_service_content)
            if verbose:
                print(f"  Created: {pt_service}")

    subprocess.run(["systemctl", "daemon-reload"], check=False)
    return True


# ═══════════════════════════════════════════════════════════════════════════
# CLI Commands
# ═══════════════════════════════════════════════════════════════════════════

def cmd_init(args):
    """Initialize MOLE directory structure and config"""
    import getpass

    print(f"MOLE v{__version__} - Setup Wizard")
    print("=" * 50)

    config_dir = Path(DEFAULT_CONFIG_DIR)
    state_dir = Path(DEFAULT_STATE_DIR)
    providers_dir = config_dir / "providers"
    config_file = Path(DEFAULT_CONFIG_FILE)

    if os.geteuid() != 0:
        print("Error: init must be run as root (sudo mole init)")
        return 1

    # Create directories
    print(f"\nCreating directories...")
    for d, mode in [(config_dir, 0o755), (state_dir, 0o700), (providers_dir, 0o755)]:
        if not d.exists():
            d.mkdir(parents=True, mode=mode)
            print(f"  Created: {d}")
        else:
            d.chmod(mode)
            print(f"  Exists:  {d}")

    # Write PIA CA cert (needed even if using ProtonVPN, for potential switch)
    pia_cert_path = providers_dir / "pia-ca.crt"
    pia_cert_path.write_text(PIA_CA_CERT)
    print(f"  Created: {pia_cert_path}")

    # Check if config exists
    if config_file.exists() and not args.force:
        print(f"\nConfig file already exists: {config_file}")
        response = input("Run interactive setup anyway? [y/N]: ").strip().lower()
        if response not in ('y', 'yes'):
            print("\nSetup skipped. Use --force to overwrite config.")
            print(f"Or edit manually: {config_file}")
            return 0

    # VPN Provider Selection
    print(f"\n{'=' * 50}")
    print("VPN Provider Selection")
    print(f"{'=' * 50}")
    print("\nSupported VPN providers:")
    print("  1. PIA (Private Internet Access)")
    print("  2. ProtonVPN")
    provider_choice = input("\nSelect provider [1]: ").strip()
    vpn_provider = "proton" if provider_choice == '2' else "pia"

    # Provider-specific setup
    vpn_user = ""
    vpn_pass = ""
    best_region = None
    proton_country = ""
    proton_tier = 2
    proton_netshield = 0

    if vpn_provider == "proton":
        # Check for proton-client dependency
        print("\nChecking dependencies...")
        try:
            import proton
            print("  proton-client: installed")
        except ImportError:
            print("  proton-client: NOT INSTALLED")
            print("\nProtonVPN requires the proton-client package.")
            print("Install with: pip3 install proton-client")
            print("\nThen re-run: sudo mole init")
            return 1

        # ProtonVPN setup
        print(f"\n{'=' * 50}")
        print("ProtonVPN Setup")
        print(f"{'=' * 50}")

        print("\nEnter your ProtonVPN credentials:")
        print("(Use your Proton account email and password)")
        vpn_user = input("  Email: ").strip()
        if not vpn_user:
            print("Error: Email is required")
            return 1

        vpn_pass = getpass.getpass("  Password: ")
        if not vpn_pass:
            print("Error: Password is required")
            return 1

        # ProtonVPN tier
        print("\nProtonVPN account tier:")
        print("  0 = Free")
        print("  1 = Basic")
        print("  2 = Plus/Visionary (required for port forwarding)")
        tier_input = input("Select tier [2]: ").strip()
        if tier_input in ('0', '1', '2'):
            proton_tier = int(tier_input)

        # Country selection
        print("\nPreferred country (2-letter code, e.g., US, NL, CH):")
        print("(Leave empty for automatic selection)")
        print("(Comma-separated for fallback: NL,DE,CH)")
        proton_country = input("  Country []: ").strip().upper()

        # NetShield
        if proton_tier >= 2:
            print("\nNetShield DNS filtering (Plus feature):")
            print("  0 = Off")
            print("  1 = Block malware")
            print("  2 = Block malware + ads + trackers")
            ns_input = input("Select [0]: ").strip()
            if ns_input in ('0', '1', '2'):
                proton_netshield = int(ns_input)

    else:
        # PIA setup
        print(f"\n{'=' * 50}")
        print("PIA (Private Internet Access) Setup")
        print(f"{'=' * 50}")

        print("\nEnter your PIA credentials:")
        vpn_user = input("  Username: ").strip()
        if not vpn_user:
            print("Error: Username is required")
            return 1

        vpn_pass = getpass.getpass("  Password: ")
        if not vpn_pass:
            print("Error: Password is required")
            return 1

    # Port forwarding
    print("\nPort forwarding allows incoming connections (needed for torrents).")
    if vpn_provider == "proton" and proton_tier < 2:
        print("Note: Port forwarding requires ProtonVPN Plus plan.")
        port_forward = False
    else:
        pf_response = input("Enable port forwarding? [Y/n]: ").strip().lower()
        port_forward = pf_response not in ('n', 'no')

    # Check natpmpc for ProtonVPN port forwarding
    if vpn_provider == "proton" and port_forward:
        result = subprocess.run(["which", "natpmpc"], capture_output=True)
        if result.returncode != 0:
            print("\nWarning: natpmpc is not installed.")
            print("Port forwarding requires natpmpc: apt install natpmpc")
            print("Continuing without port forwarding verification...")

    # Torrent client
    torrent_client = "none"
    qb_port = 8080
    qb_user = os.environ.get('SUDO_USER', 'root')
    if port_forward:
        print("\nTorrent client integration (auto-updates listening port):")
        print("  1. qBittorrent")
        print("  2. None")
        tc_response = input("Select [1]: ").strip()
        if tc_response != '2':
            torrent_client = "qbittorrent"
            qb_port_str = input("  qBittorrent Web UI port [8080]: ").strip()
            qb_port = 8080
            if qb_port_str.isdigit():
                port_val = int(qb_port_str)
                if 1 <= port_val <= 65535:
                    qb_port = port_val
                else:
                    print(f"    Invalid port {port_val}, using default 8080")
            elif qb_port_str:
                print(f"    Invalid port '{qb_port_str}', using default 8080")
            qb_user_input = input(f"  Run qBittorrent as user [{qb_user}]: ").strip()
            if qb_user_input:
                qb_user = qb_user_input

    # Detect network interface
    print("\nDetecting network interface...")
    host_interface = "eth0"
    try:
        result = run_cmd(["ip", "route", "show", "default"], check=False)
        if result.returncode == 0 and "dev" in result.stdout:
            parts = result.stdout.split()
            if "dev" in parts:
                idx = parts.index("dev") + 1
                if idx < len(parts):
                    host_interface = parts[idx]
    except Exception:
        pass
    print(f"  Detected: {host_interface}")

    # Auto-detect best region (PIA only)
    if vpn_provider == "pia":
        print(f"\n{'=' * 50}")
        print("Finding best region...")
        print(f"{'=' * 50}")

        try:
            regions = _fetch_pia_regions()
            pf_regions = [r for r in regions if r.get("port_forward")] if port_forward else regions

            if pf_regions:
                print(f"Testing {len(pf_regions)} regions...")

                def ping_region(r):
                    servers = r.get("servers", [])
                    if servers:
                        latency = _ping_server(servers[0]["ip"])
                        return (r, latency)
                    return (r, None)

                results = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    futures = [executor.submit(ping_region, r) for r in pf_regions]
                    for future in concurrent.futures.as_completed(futures):
                        region, latency = future.result()
                        if latency is not None:
                            results.append((region, latency))

                if results:
                    results.sort(key=lambda x: x[1])
                    best_region = results[0][0]['id']
                    best_name = results[0][0]['name']
                    best_latency = results[0][1]
                    print(f"\nBest region: {best_name} ({best_region}) - {best_latency:.1f} ms")

                    if len(results) > 1:
                        print("\nTop 5 regions:")
                        for i, (r, lat) in enumerate(results[:5], 1):
                            marker = " <-- selected" if i == 1 else ""
                            print(f"  {i}. {r['name']:<30} {lat:.1f} ms{marker}")
        except Exception as e:
            print(f"Warning: Could not auto-detect region: {e}")

        if not best_region:
            print("\nCould not auto-detect region. Using default: ca_toronto")
            best_region = "ca_toronto"

    # DNS over TLS
    print(f"\n{'=' * 50}")
    print("DNS over TLS (encrypted DNS with optional ad-blocking)")
    print(f"{'=' * 50}")
    dot_enabled = False
    dot_upstream = "cloudflare"
    dot_block_ads = False
    dot_block_malware = False
    dot_custom_server = ""

    dot_response = input("\nEnable DNS over TLS? [y/N]: ").strip().lower()
    if dot_response in ('y', 'yes'):
        dot_enabled = True
        print("\nSelect DNS provider:")
        print("  1. Cloudflare (1.1.1.1) - Fast, privacy-focused")
        print("  2. Cloudflare Family - Blocks malware & adult content")
        print("  3. Quad9 (9.9.9.9) - Blocks malware")
        print("  4. Google (8.8.8.8)")
        print("  5. Custom (enter your own DoT server)")
        dns_choice = input("Select [1]: ").strip()
        if dns_choice == '2':
            dot_upstream = "cloudflare-family"
        elif dns_choice == '3':
            dot_upstream = "quad9"
        elif dns_choice == '4':
            dot_upstream = "google"
        elif dns_choice == '5':
            dot_upstream = "custom"
            dot_custom_server = input("  Enter DoT server (ip:port, e.g. 9.9.9.9:853): ").strip()
            if not dot_custom_server:
                print("  No server entered, using Cloudflare")
                dot_upstream = "cloudflare"

        print("\nAd & tracker blocking (uses auto-updating blocklists):")
        block_response = input("Block ads and trackers? [Y/n]: ").strip().lower()
        if block_response not in ('n', 'no'):
            dot_block_ads = True

        malware_response = input("Block malware domains? [Y/n]: ").strip().lower()
        if malware_response not in ('n', 'no'):
            dot_block_malware = True

    # HTTP Proxy
    print(f"\n{'=' * 50}")
    print("HTTP Proxy (route other apps through VPN)")
    print(f"{'=' * 50}")
    proxy_enabled = False
    proxy_user = ""
    proxy_pass = ""

    proxy_response = input("\nEnable HTTP proxy? [y/N]: ").strip().lower()
    if proxy_response in ('y', 'yes'):
        proxy_enabled = True
        print("\nProxy authentication (required):")
        proxy_user = input("  Proxy username [mole]: ").strip() or "mole"
        proxy_pass = getpass.getpass("  Proxy password: ")
        if not proxy_pass:
            import secrets
            proxy_pass = secrets.token_urlsafe(16)
            print(f"  Generated password: {proxy_pass}")

    # HTTP API
    print(f"\n{'=' * 50}")
    print("HTTP Control API (query/control VPN via REST API)")
    print(f"{'=' * 50}")
    api_enabled = False
    api_key = ""

    api_response = input("\nEnable HTTP API? [y/N]: ").strip().lower()
    if api_response in ('y', 'yes'):
        api_enabled = True
        import secrets
        api_key = secrets.token_urlsafe(32)
        print(f"\nGenerated API key: {api_key}")
        print("(Save this - you'll need it to access the API)")

    # Write config
    print(f"\n{'=' * 50}")
    print("Writing configuration...")
    print(f"{'=' * 50}")

    config_content = f"""# MOLE Configuration
# Generated by setup wizard

# VPN Provider
VPN_PROVIDER={vpn_provider}
"""

    if vpn_provider == "proton":
        config_content += f"""
# ProtonVPN Credentials
PROTON_USER={vpn_user}
PROTON_PASS={vpn_pass}

# Account tier (0=free, 1=basic, 2=plus)
PROTON_TIER={proton_tier}
"""
        if proton_country:
            config_content += f"""
# Country (or comma-separated fallback list)
PROTON_COUNTRY={proton_country}
"""
        if proton_netshield > 0:
            config_content += f"""
# NetShield (0=off, 1=malware, 2=malware+ads+trackers)
PROTON_NETSHIELD={proton_netshield}
"""
        if port_forward:
            config_content += """
# Keep port forwarding alive (ProtonVPN NAT-PMP requires ~45s refresh)
KEEPALIVE_INTERVAL=45
"""
    else:
        config_content += f"""
# PIA Credentials
PIA_USER={vpn_user}
PIA_PASS={vpn_pass}

# Region (auto-detected, or comma-separated fallback list)
PIA_REGION={best_region}

# Dedicated IP (optional - uncomment if you have a PIA Dedicated IP)
# PIA_DIP_TOKEN=dip_xxxxxxxxxxxxxxxx

# Max latency threshold for server selection (optional, in ms)
# PIA_MAX_LATENCY=100
"""

    config_content += f"""
# Network Namespace
NETNS_NAME=vpn
VETH_HOST_IP=10.200.200.1
VETH_VPN_IP=10.200.200.2

# Host network interface
HOST_INTERFACE={host_interface}

# Port Forwarding
PORT_FORWARD={'true' if port_forward else 'false'}

# Torrent Client
TORRENT_CLIENT={torrent_client}
"""

    if torrent_client == "qbittorrent":
        config_content += f"""QB_PORT={qb_port}
QB_USER={qb_user}
"""

    if dot_enabled:
        config_content += f"""
# DNS over TLS
DOT_ENABLED=true
DOT_UPSTREAM={dot_upstream}
"""
        if dot_upstream == "custom" and dot_custom_server:
            config_content += f"DOT_CUSTOM_SERVER={dot_custom_server}\n"
        config_content += f"""DOT_BLOCK_ADS={'true' if dot_block_ads else 'false'}
DOT_BLOCK_MALWARE={'true' if dot_block_malware else 'false'}
DOT_CACHING=true
DOT_UPDATE_PERIOD=24h
"""
    else:
        config_content += """
# DNS over TLS (disabled)
DOT_ENABLED=false
"""

    if proxy_enabled:
        config_content += f"""
# HTTP Proxy
PROXY_ENABLED=true
PROXY_PORT=8888
PROXY_BIND=10.200.200.1
PROXY_USER={proxy_user}
PROXY_PASS={proxy_pass}
"""
    else:
        config_content += """
# HTTP Proxy (disabled)
PROXY_ENABLED=false
"""

    if api_enabled:
        config_content += f"""
# HTTP Control API
HTTP_API_ENABLED=true
HTTP_API_PORT=8080
HTTP_API_BIND=127.0.0.1
HTTP_API_KEY={api_key}
"""
    else:
        config_content += """
# HTTP Control API (disabled)
HTTP_API_ENABLED=false
"""

    config_file.write_text(config_content)
    config_file.chmod(0o600)
    print(f"  Created: {config_file}")

    # Summary
    print(f"\n{'=' * 50}")
    print("Setup Complete!")
    print(f"{'=' * 50}")
    print(f"\nConfiguration:")
    if vpn_provider == "proton":
        print(f"  Provider:        ProtonVPN")
        print(f"  Tier:            {['Free', 'Basic', 'Plus'][proton_tier]}")
        if proton_country:
            print(f"  Country:         {proton_country}")
        if proton_netshield > 0:
            print(f"  NetShield:       Level {proton_netshield}")
    else:
        print(f"  Provider:        PIA")
        print(f"  Region:          {best_region}")
    print(f"  Port Forwarding: {'Yes' if port_forward else 'No'}")
    if torrent_client == "qbittorrent":
        print(f"  Torrent Client:  qBittorrent (port {qb_port})")
    else:
        print(f"  Torrent Client:  {torrent_client}")
    print(f"  Interface:       {host_interface}")
    if dot_enabled:
        print(f"  DNS over TLS:    Yes ({dot_upstream})")
    else:
        print(f"  DNS over TLS:    No")
    print(f"  HTTP Proxy:      {'Yes (port 8888)' if proxy_enabled else 'No'}")
    print(f"  HTTP API:        {'Yes (port 8080)' if api_enabled else 'No'}")

    # Start service
    print(f"\n{'=' * 50}")
    print("Starting MOLE Service")
    print(f"{'=' * 50}")

    print("\nStarting MOLE...")
    subprocess.run(["systemctl", "start", "mole"], check=False)

    print("Waiting for VPN connection", end="", flush=True)
    vpn_connected = False
    for i in range(30):
        time.sleep(1)
        print(".", end="", flush=True)
        result = run_in_netns(["ip", "link", "show", "mole"], "vpn", check=False)
        if result.returncode == 0 and "state UP" in result.stdout:
            vpn_connected = True
            break
    print()

    if vpn_connected:
        print("VPN connected!")
        result = run_in_netns(["curl", "-s", "-m", "5", "https://ipinfo.io/ip"], "vpn", check=False)
        if result.returncode == 0 and result.stdout.strip():
            print(f"Public IP: {result.stdout.strip()}")
    else:
        print("VPN is still connecting...")
        print("Check status with: sudo mole status")

    # qBittorrent setup
    if torrent_client == "qbittorrent" and vpn_connected:
        print(f"\n{'=' * 50}")
        print("qBittorrent Setup")
        print(f"{'=' * 50}")

        qb_response = input("\nSetup qBittorrent in VPN namespace? [Y/n]: ").strip().lower()
        if qb_response in ('', 'y', 'yes'):
            result = subprocess.run(["which", "qbittorrent-nox"], capture_output=True)
            if result.returncode != 0:
                print("\nqbittorrent-nox is not installed.")
                print("Install it with: sudo apt install qbittorrent-nox")
            else:
                config = Config()
                enable_passthrough = False

                passthrough_response = input(f"Also make it accessible at http://localhost:{qb_port}? [Y/n]: ").strip().lower()
                if passthrough_response in ('', 'y', 'yes'):
                    socat_result = subprocess.run(["which", "socat"], capture_output=True)
                    if socat_result.returncode != 0:
                        print("\n  socat is not installed (needed for localhost passthrough)")
                        print("  Install with: sudo apt install socat")
                    else:
                        enable_passthrough = True

                print("\nSetting up qBittorrent service...")
                _qbittorrent_setup_services(enable_passthrough=enable_passthrough, verbose=False)

                subprocess.run(["systemctl", "enable", "qbittorrent-mole"], check=False)
                subprocess.run(["systemctl", "start", "qbittorrent-mole"], check=False)
                print("  Service enabled and started!")

                if enable_passthrough:
                    subprocess.run(["systemctl", "enable", "qbittorrent-passthrough"], check=False)
                    subprocess.run(["systemctl", "start", "qbittorrent-passthrough"], check=False)
                    print(f"\nqBittorrent Web UI: http://localhost:{qb_port}")
                else:
                    print(f"\nqBittorrent Web UI: http://{config.veth_vpn_ip}:{qb_port}")
                print("Default login: admin / adminadmin")

    # Final instructions
    print(f"\n{'=' * 50}")
    print("Setup Complete!")
    print(f"{'=' * 50}")
    print("\nUseful commands:")
    print("  sudo mole status      - Check VPN status")
    print("  sudo mole logs -f     - Follow logs")
    print("  mole autoselect       - Find faster region")

    return 0


def cmd_status(args):
    """Show current MOLE status"""
    state_dir = Path(DEFAULT_STATE_DIR)
    netns = "vpn"

    print(f"MOLE v{__version__} - Status")
    print("=" * 40)

    if os.geteuid() != 0:
        print("\nNote: Run with sudo for full status (sudo mole status)")
        print("      Some information may be unavailable.\n")

    result = subprocess.run(
        ["systemctl", "is-active", "mole"],
        capture_output=True, text=True
    )
    service_status = result.stdout.strip()
    print(f"\nService: {service_status}")

    result = run_cmd(["ip", "netns", "list"], check=False)
    ns_exists = netns in result.stdout
    print(f"Namespace '{netns}': {'exists' if ns_exists else 'missing'}")

    if not ns_exists:
        return 0

    result = run_in_netns(["ip", "link", "show", "mole"], netns, check=False)
    if "Operation not permitted" in result.stderr:
        print(f"WireGuard interface: (requires sudo)")
        wg_up = False
    else:
        wg_up = result.returncode == 0
        print(f"WireGuard interface: {'up' if wg_up else 'down'}")

    if wg_up:
        result = run_in_netns(["wg", "show", "mole"], netns, check=False)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'endpoint:' in line:
                    print(f"  Endpoint: {line.split('endpoint:')[1].strip()}")
                if 'latest handshake:' in line:
                    print(f"  Last handshake: {line.split('latest handshake:')[1].strip()}")
                if 'transfer:' in line:
                    print(f"  Transfer: {line.split('transfer:')[1].strip()}")

    print(f"\nState:")
    for name in ["hostname", "server_ip", "port"]:
        state_file = state_dir / name
        if state_file.exists():
            print(f"  {name}: {state_file.read_text().strip()}")

    if wg_up:
        result = run_in_netns(["curl", "-s", "-m", "5", "https://ipinfo.io/ip"], netns, check=False)
        if result.returncode == 0:
            print(f"  public_ip: {result.stdout.strip()}")

        result = run_in_netns([
            "iptables", "-L", "OUTPUT", "-n"
        ], netns, check=False)
        if "DROP" in result.stdout:
            print(f"  Kill switch: enabled")
        else:
            print(f"  Kill switch: disabled")

    return 0


def cmd_ip(args):
    """Show current public IP through VPN"""
    netns = "vpn"

    result = run_cmd(["ip", "netns", "list"], check=False)
    if netns not in result.stdout:
        print("VPN namespace not running")
        return 1

    result = run_in_netns(["curl", "-s", "-m", "5", "https://ipinfo.io/ip"], netns, check=False)
    if result.returncode == 0 and result.stdout.strip():
        print(result.stdout.strip())
        return 0
    else:
        print("Failed to get public IP (VPN may be down)")
        return 1


def cmd_regions(args):
    """List available VPN regions"""
    provider = getattr(args, 'provider', None)

    # Auto-detect provider from config if not specified
    if not provider:
        try:
            config = Config()
            provider = config.vpn_provider.lower()
        except Exception:
            provider = 'pia'
    else:
        provider = provider.lower()

    if provider not in ('pia', 'proton'):
        print(f"Error: Provider '{provider}' is not supported")
        print("Supported providers: pia, proton")
        return 1

    pf_only = getattr(args, 'port_forward', False)
    show_servers = getattr(args, 'servers', False)
    tier = getattr(args, 'tier', 2)

    try:
        if provider == 'proton':
            return _cmd_regions_proton(pf_only, show_servers, tier)
        else:
            return _cmd_regions_pia(pf_only, show_servers)
    except Exception as e:
        print(f"Error fetching regions: {e}")
        return 1


def _cmd_regions_pia(pf_only: bool, show_servers: bool) -> int:
    """List PIA regions"""
    print(f"MOLE v{__version__} - Available PIA Regions")
    print("=" * 60)

    regions = _fetch_pia_regions()
    if pf_only:
        regions = [r for r in regions if r.get("port_forward")]
    regions.sort(key=lambda x: x["name"])

    if show_servers:
        total_servers = 0
        for r in regions:
            pf = "Yes" if r.get("port_forward") else "No"
            servers = r.get("servers", [])
            total_servers += len(servers)
            print(f"\n{r['id']} ({r['name']}) - Port Forward: {pf}")
            print(f"  Servers ({len(servers)}):")
            for s in servers:
                print(f"    - {s['cn']} ({s['ip']})")
        print(f"\n{'=' * 60}")
        print(f"Total: {len(regions)} regions, {total_servers} servers")
    else:
        print(f"\n{'Region ID':<25} {'Name':<30} {'Port Forward'}")
        print("-" * 60)
        for r in regions:
            pf = "Yes" if r.get("port_forward") else "No"
            print(f"{r['id']:<25} {r['name']:<30} {pf}")
        print(f"\nTotal: {len(regions)} regions")

    return 0


def _cmd_regions_proton(pf_only: bool, show_servers: bool, tier: int) -> int:
    """List ProtonVPN countries/servers"""
    print(f"MOLE v{__version__} - Available ProtonVPN Countries")
    print("=" * 60)
    print(f"(Showing servers for tier {tier}: {['Free', 'Basic', 'Plus'][tier]})")

    servers = _fetch_proton_servers(tier)

    if pf_only:
        servers = [s for s in servers if s["has_p2p"]]
        print("(Filtered to P2P servers - required for port forwarding)")

    countries = _get_proton_countries(servers)
    sorted_countries = sorted(countries.values(), key=lambda x: x["name"])

    if show_servers:
        total_servers = 0
        for country in sorted_countries:
            p2p = "Yes" if country["has_p2p"] else "No"
            country_servers = sorted(country["servers"], key=lambda x: x["load"])
            total_servers += len(country_servers)
            print(f"\n{country['code']} ({country['name']}) - P2P: {p2p}")
            print(f"  Servers ({len(country_servers)}):")
            for s in country_servers[:10]:  # Show top 10 by load
                p2p_flag = " [P2P]" if s["has_p2p"] else ""
                city = f" ({s['city']})" if s["city"] else ""
                print(f"    - {s['name']:<15} {s['load']:>3}% load{city}{p2p_flag}")
            if len(country_servers) > 10:
                print(f"    ... and {len(country_servers) - 10} more servers")
        print(f"\n{'=' * 60}")
        print(f"Total: {len(sorted_countries)} countries, {total_servers} servers")
    else:
        print(f"\n{'Country':<8} {'Name':<30} {'Servers':<10} {'P2P'}")
        print("-" * 60)
        for country in sorted_countries:
            p2p = "Yes" if country["has_p2p"] else "No"
            print(f"{country['code']:<8} {country['name']:<30} {len(country['servers']):<10} {p2p}")
        print(f"\nTotal: {len(sorted_countries)} countries, {len(servers)} servers")

    return 0


def cmd_restart(args):
    """Force VPN reconnection"""
    print(f"MOLE v{__version__} - Restart")

    if os.geteuid() != 0:
        print("Error: restart must be run as root (sudo mole restart)")
        return 1

    result = subprocess.run(
        ["systemctl", "is-active", "mole"],
        capture_output=True, text=True
    )

    if result.stdout.strip() != "active":
        print("Error: MOLE service is not running")
        print("Start with: sudo systemctl start mole")
        return 1

    # Handle --new-server flag
    if getattr(args, 'new_server', False):
        print("Requesting new server...")
        state_dir = Path(DEFAULT_STATE_DIR)
        (state_dir / "new-server").touch()

    print("Restarting MOLE service...")
    result = subprocess.run(
        ["systemctl", "restart", "mole"],
        capture_output=True, text=True
    )

    if result.returncode == 0:
        if getattr(args, 'new_server', False):
            print("Restart initiated with new server. Check status with: sudo mole status")
        else:
            print("Restart initiated. Check status with: sudo mole status")
    else:
        print(f"Restart failed: {result.stderr}")
        return 1

    return 0


def cmd_start(args):
    """Start the MOLE service"""
    if os.geteuid() != 0:
        print("Error: start requires root (sudo mole start)")
        return 1

    result = subprocess.run(
        ["systemctl", "is-active", "mole"],
        capture_output=True, text=True
    )

    if result.stdout.strip() == "active":
        print("MOLE service is already running")
        print("Use 'sudo mole restart' to reconnect")
        return 0

    print("Starting MOLE service...")
    result = subprocess.run(
        ["systemctl", "start", "mole"],
        capture_output=True, text=True
    )

    if result.returncode == 0:
        print("MOLE service started")
        print("Check status with: sudo mole status")
    else:
        print(f"Start failed: {result.stderr}")
        return 1

    return 0


def cmd_stop(args):
    """Stop the MOLE service"""
    if os.geteuid() != 0:
        print("Error: stop requires root (sudo mole stop)")
        return 1

    result = subprocess.run(
        ["systemctl", "is-active", "mole"],
        capture_output=True, text=True
    )

    if result.stdout.strip() != "active":
        print("MOLE service is not running")
        return 0

    print("Stopping MOLE service...")
    result = subprocess.run(
        ["systemctl", "stop", "mole"],
        capture_output=True, text=True
    )

    if result.returncode == 0:
        print("MOLE service stopped")
    else:
        print(f"Stop failed: {result.stderr}")
        return 1

    return 0


def cmd_logs(args):
    """Show MOLE logs"""
    cmd = ["journalctl", "-u", "mole"]

    if args.follow:
        cmd.append("-f")
    if args.lines:
        cmd.extend(["-n", str(args.lines)])

    os.execvp("journalctl", cmd)


def cmd_validate(args):
    """Validate configuration file"""
    print(f"MOLE v{__version__} - Config Validation")
    print("=" * 40)

    config_path = args.config if hasattr(args, 'config') and args.config else DEFAULT_CONFIG_FILE
    print(f"\nChecking: {config_path}")

    is_valid, issues = validate_config(config_path)

    if not issues:
        print("\nConfiguration is valid!")
        return 0

    print(f"\nFound {len(issues)} issue(s):\n")
    for issue in issues:
        if issue.startswith("Warning:"):
            print(f"  [WARN] {issue[9:]}")
        else:
            print(f"  [ERROR] {issue}")

    if is_valid:
        print("\nConfiguration is valid (with warnings)")
        return 0
    else:
        print("\nConfiguration has errors - please fix before running")
        return 1


def cmd_dns(args):
    """Test DNS over TLS functionality"""
    config = Config(args.config if hasattr(args, 'config') and args.config else DEFAULT_CONFIG_FILE)

    print(f"MOLE v{__version__} - DNS over TLS Test")
    print("=" * 50)

    if not config.dot_enabled:
        print("\nDNS over TLS is not enabled in config")
        print("  Add DOT_ENABLED=true to your config file")
        return 1

    dot_bind = config.dot_bind
    dot_port = config.dot_port

    print(f"\nDOT Server: {dot_bind}:{dot_port}")
    print(f"Upstream: {config.dot_upstream}")
    print(f"Block ads: {config.dot_block_ads}")
    print(f"Block malware: {config.dot_block_malware}")

    test_domains = [
        ("google.com", "Normal resolution"),
        ("cloudflare.com", "Normal resolution"),
    ]

    if config.dot_block_ads:
        test_domains.append(("doubleclick.net", "Should be BLOCKED (ads)"))

    print("\n" + "-" * 50)
    print("DNS Resolution Tests")
    print("-" * 50)

    use_namespace = args.namespace if hasattr(args, 'namespace') and args.namespace else False

    for domain, description in test_domains:
        print(f"\n{domain}")
        print(f"  Expected: {description}")

        dig_cmd = ["dig", "+short", "+time=5", "+tries=2", f"@{dot_bind}", domain]

        try:
            if use_namespace:
                result = run_in_netns(dig_cmd, config.netns, check=False)
            else:
                result = subprocess.run(dig_cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                output = result.stdout.strip()
                if output:
                    ips = output.split('\n')[:2]
                    print(f"  Result: Resolved -> {', '.join(ips)}")
                else:
                    print(f"  Result: BLOCKED (NXDOMAIN)")
            else:
                print(f"  Result: Query failed (server may not be running)")

        except subprocess.TimeoutExpired:
            print(f"  Result: Timeout (server may not be running)")
        except Exception as e:
            print(f"  Result: Error: {e}")

    return 0


def cmd_apikey(args):
    """Generate or show API key"""
    import secrets

    action = args.action if hasattr(args, 'action') and args.action else 'generate'
    config_path = args.config if hasattr(args, 'config') and args.config else DEFAULT_CONFIG_FILE

    if action == 'generate':
        existing_key = None
        try:
            config = Config(config_path)
            existing_key = config.http_api_key
        except Exception:
            pass

        if existing_key:
            print(f"An API key already exists in config.")
            response = input("\nGenerate a new key and replace it? [y/N]: ").strip().lower()
            if response not in ('y', 'yes'):
                print("Aborted.")
                return 0

        api_key = secrets.token_urlsafe(32)

        print(f"MOLE v{__version__} - API Key Generator")
        print("=" * 50)
        print(f"\nGenerated API Key:\n")
        print(f"  {api_key}")

        response = input(f"\nAdd this key to {config_path}? [Y/n]: ").strip().lower()
        if response in ('', 'y', 'yes'):
            try:
                with open(config_path, 'r') as f:
                    config_content = f.read()

                if re.search(r'^HTTP_API_KEY=', config_content, re.MULTILINE):
                    config_content = re.sub(
                        r'^HTTP_API_KEY=.*$',
                        f'HTTP_API_KEY={api_key}',
                        config_content,
                        flags=re.MULTILINE
                    )
                else:
                    if not config_content.endswith('\n'):
                        config_content += '\n'
                    config_content += f'\n# HTTP API Authentication\nHTTP_API_KEY={api_key}\n'

                with open(config_path, 'w') as f:
                    f.write(config_content)

                print(f"\nAPI key added to {config_path}")
                print("Restart MOLE for the new key to take effect: sudo systemctl restart mole")
            except PermissionError:
                print(f"\nError: Permission denied writing to {config_path}")
                print(f"\n  HTTP_API_KEY={api_key}")
            except Exception as e:
                print(f"\nError updating config: {e}")
        else:
            print(f"\nAdd this to your config file ({config_path}):\n")
            print(f"  HTTP_API_KEY={api_key}")

        print(f"\nUsage examples:\n")
        print(f"  curl -H 'X-API-Key: {api_key}' http://127.0.0.1:8080/v1/status")

    elif action == 'show':
        try:
            config = Config(config_path)
        except PermissionError:
            print(f"Error: Permission denied reading {config_path}")
            return 1

        api_key = config.http_api_key

        print(f"MOLE v{__version__} - API Key Status")
        print("=" * 50)

        if api_key:
            print(f"\nAPI Key configured: Yes")
            print(f"\nCurrent key:\n")
            print(f"  {api_key}")
        else:
            print(f"\nAPI Key configured: No")
            print(f"\nRun 'mole api-key generate' to create one")

    return 0


def cmd_autoselect(args):
    """Auto-select the best region/server based on latency"""
    test_servers = getattr(args, 'servers', False)
    region_filter = getattr(args, 'region', None)
    tier = getattr(args, 'tier', 2)

    # Auto-detect provider from config
    provider = None
    try:
        config = Config()
        provider = config.vpn_provider.lower()
    except Exception:
        provider = 'pia'

    if test_servers:
        print(f"MOLE v{__version__} - Auto-Select Server ({provider.upper()})")
    else:
        print(f"MOLE v{__version__} - Auto-Select {'Country' if provider == 'proton' else 'Region'} ({provider.upper()})")
    print("=" * 50)

    try:
        if provider == 'proton':
            return _cmd_autoselect_proton(test_servers, region_filter, tier)
        else:
            return _cmd_autoselect_pia(test_servers, region_filter)
    except Exception as e:
        print(f"Error: {e}")
        return 1


def _cmd_autoselect_pia(test_servers: bool, region_filter: str) -> int:
    """Auto-select best PIA region/server"""
    print("\nFetching regions with port forwarding support...")

    regions = _fetch_pia_regions()
    pf_regions = [r for r in regions if r.get("port_forward")]

    if region_filter:
        pf_regions = [r for r in pf_regions if r["id"] == region_filter]
        if not pf_regions:
            print(f"Error: Region '{region_filter}' not found or has no port forwarding")
            return 1
        print(f"Testing servers in region: {region_filter}")
    else:
        print(f"Found {len(pf_regions)} regions with port forwarding")

    if not pf_regions:
        print("Error: No regions with port forwarding found")
        return 1

    if test_servers:
        all_servers = []
        for region in pf_regions:
            for server in region.get("servers", []):
                all_servers.append({
                    "region_id": region["id"],
                    "region_name": region["name"],
                    "hostname": server["cn"],
                    "ip": server["ip"]
                })

        print(f"\nTesting {len(all_servers)} servers (this may take a few minutes)...")

        results = []

        def test_server(srv):
            latency = _ping_server(srv["ip"])
            return (srv, latency)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(test_server, s): s for s in all_servers}
            for future in concurrent.futures.as_completed(futures):
                srv, latency = future.result()
                if latency is not None:
                    results.append((srv, latency))
                    print(f"  {srv['hostname']:<25} {latency:.1f} ms  ({srv['region_name']})")

        if not results:
            print("\nError: Could not reach any servers")
            return 1

        results.sort(key=lambda x: x[1])

        print(f"\n{'=' * 50}")
        print("Top 10 fastest servers:")
        print(f"{'=' * 50}")
        for i, (srv, latency) in enumerate(results[:10], 1):
            print(f"  {i}. {srv['hostname']:<25} {latency:.1f} ms  ({srv['region_id']})")

        best = results[0][0]
        best_latency = results[0][1]
        print(f"\nRecommended server: {best['hostname']} ({best_latency:.1f} ms)")

        response = input(f"\nApply this server to {DEFAULT_CONFIG_FILE}? [Y/n]: ").strip().lower()
        if response in ('', 'y', 'yes'):
            _apply_region_to_config(best['region_id'], best['hostname'])
        else:
            print(f"\nTo use this server, set in {DEFAULT_CONFIG_FILE}:")
            print(f"  PIA_REGION={best['region_id']}")
            print(f"  PIA_SERVER={best['hostname']}")

    else:
        print("\nTesting latency to each region (this may take a minute)...")

        results = []

        def test_region(region):
            servers = region.get("servers", [])
            if servers:
                latency = _ping_server(servers[0].get("ip"))
                return (region, latency)
            return (region, None)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(test_region, r): r for r in pf_regions}
            for future in concurrent.futures.as_completed(futures):
                region, latency = future.result()
                if latency is not None:
                    results.append((region, latency))
                    print(f"  {region['name']:<30} {latency:.1f} ms")

        if not results:
            print("\nError: Could not reach any servers")
            return 1

        results.sort(key=lambda x: x[1])

        print(f"\n{'=' * 50}")
        print("Top 5 fastest regions:")
        print(f"{'=' * 50}")
        for i, (region, latency) in enumerate(results[:5], 1):
            print(f"  {i}. {region['name']:<30} {latency:.1f} ms  (ID: {region['id']})")

        best = results[0][0]
        best_latency = results[0][1]
        print(f"\nRecommended region: {best['id']} ({best_latency:.1f} ms)")

        response = input(f"\nApply this region to {DEFAULT_CONFIG_FILE}? [Y/n]: ").strip().lower()
        if response in ('', 'y', 'yes'):
            _apply_region_to_config(best['id'])
        else:
            print(f"\nTo use this region, set in {DEFAULT_CONFIG_FILE}:")
            print(f"  PIA_REGION={best['id']}")

    return 0


def _cmd_autoselect_proton(test_servers: bool, country_filter: str, tier: int) -> int:
    """Auto-select best ProtonVPN country/server"""
    print("\nFetching servers with P2P support (required for port forwarding)...")
    print(f"(Tier {tier}: {['Free', 'Basic', 'Plus'][tier]})")

    servers = _fetch_proton_servers(tier)
    p2p_servers = [s for s in servers if s["has_p2p"]]

    if country_filter:
        country_filter = country_filter.upper()
        p2p_servers = [s for s in p2p_servers if s["country"] == country_filter]
        if not p2p_servers:
            print(f"Error: Country '{country_filter}' not found or has no P2P servers")
            return 1
        print(f"Testing servers in country: {country_filter}")
    else:
        print(f"Found {len(p2p_servers)} P2P servers")

    if not p2p_servers:
        print("Error: No P2P servers found (may require Plus plan)")
        return 1

    if test_servers:
        print(f"\nTesting {len(p2p_servers)} servers (this may take a few minutes)...")

        results = []

        def test_server(srv):
            latency = _ping_server(srv["entry_ip"])
            return (srv, latency)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(test_server, s): s for s in p2p_servers}
            for future in concurrent.futures.as_completed(futures):
                srv, latency = future.result()
                if latency is not None:
                    results.append((srv, latency))
                    print(f"  {srv['name']:<15} {latency:.1f} ms  ({srv['country']}, {srv['load']}% load)")

        if not results:
            print("\nError: Could not reach any servers")
            return 1

        results.sort(key=lambda x: x[1])

        print(f"\n{'=' * 50}")
        print("Top 10 fastest servers:")
        print(f"{'=' * 50}")
        for i, (srv, latency) in enumerate(results[:10], 1):
            print(f"  {i}. {srv['name']:<15} {latency:.1f} ms  ({srv['country']}, {srv['load']}% load)")

        best = results[0][0]
        best_latency = results[0][1]
        print(f"\nRecommended server: {best['name']} ({best_latency:.1f} ms)")

        response = input(f"\nApply this server to {DEFAULT_CONFIG_FILE}? [Y/n]: ").strip().lower()
        if response in ('', 'y', 'yes'):
            _apply_proton_config(best['country'], best['name'])
        else:
            print(f"\nTo use this server, set in {DEFAULT_CONFIG_FILE}:")
            print(f"  PROTON_COUNTRY={best['country']}")
            print(f"  PROTON_SERVER={best['name']}")

    else:
        # Group by country and test one server per country
        countries = _get_proton_countries(p2p_servers)
        print(f"\nTesting latency to {len(countries)} countries (this may take a minute)...")

        results = []

        def test_country(country_data):
            # Pick server with lowest load for testing
            sorted_servers = sorted(country_data["servers"], key=lambda x: x["load"])
            if sorted_servers:
                latency = _ping_server(sorted_servers[0]["entry_ip"])
                return (country_data, latency)
            return (country_data, None)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(test_country, c): c for c in countries.values()}
            for future in concurrent.futures.as_completed(futures):
                country, latency = future.result()
                if latency is not None:
                    results.append((country, latency))
                    print(f"  {country['name']:<30} {latency:.1f} ms")

        if not results:
            print("\nError: Could not reach any servers")
            return 1

        results.sort(key=lambda x: x[1])

        print(f"\n{'=' * 50}")
        print("Top 5 fastest countries:")
        print(f"{'=' * 50}")
        for i, (country, latency) in enumerate(results[:5], 1):
            print(f"  {i}. {country['name']:<30} {latency:.1f} ms  ({country['code']})")

        best = results[0][0]
        best_latency = results[0][1]
        print(f"\nRecommended country: {best['code']} ({best_latency:.1f} ms)")

        response = input(f"\nApply this country to {DEFAULT_CONFIG_FILE}? [Y/n]: ").strip().lower()
        if response in ('', 'y', 'yes'):
            _apply_proton_config(best['code'])
        else:
            print(f"\nTo use this country, set in {DEFAULT_CONFIG_FILE}:")
            print(f"  PROTON_COUNTRY={best['code']}")

    return 0


def cmd_speedtest(args):
    """Test VPN connection speed"""
    netns = "vpn"

    print(f"MOLE v{__version__} - Speed Test")
    print("=" * 40)

    result = run_cmd(["ip", "netns", "list"], check=False)
    if netns not in result.stdout:
        print("Error: VPN namespace not running")
        return 1

    result = run_in_netns(["ip", "link", "show", "mole"], netns, check=False)
    if result.returncode != 0:
        print("Error: VPN interface not up")
        return 1

    print("\nTesting download speed...")

    test_urls = [
        ("Cloudflare", "https://speed.cloudflare.com/__down?bytes=104857600"),
        ("Google", "https://storage.googleapis.com/youtube-downloads/speedtest/100MB.bin"),
    ]

    for name, url in test_urls:
        print(f"\n  Testing {name}...")
        try:
            start_time = time.time()
            result = run_in_netns([
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{size_download}",
                "-m", "30",
                url
            ], netns, check=False)

            elapsed = time.time() - start_time

            if result.returncode == 0 and result.stdout.strip():
                bytes_downloaded = int(result.stdout.strip())
                if bytes_downloaded > 0 and elapsed > 0:
                    speed_mbps = (bytes_downloaded * 8) / (elapsed * 1000000)
                    speed_mbs = bytes_downloaded / (elapsed * 1000000)
                    print(f"    Downloaded: {bytes_downloaded / 1000000:.1f} MB in {elapsed:.1f}s")
                    print(f"    Speed: {speed_mbps:.1f} Mbps ({speed_mbs:.1f} MB/s)")
                    break
        except Exception as e:
            print(f"    Error: {e}")

    print("\nTesting latency...")
    state_dir = Path(DEFAULT_STATE_DIR)
    server_ip_file = state_dir / "server_ip"
    if server_ip_file.exists():
        server_ip = server_ip_file.read_text().strip()
        result = run_in_netns([
            "ping", "-c", "5", "-q", server_ip
        ], netns, check=False)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'rtt' in line or 'round-trip' in line:
                    parts = line.split('=')
                    if len(parts) >= 2:
                        times = parts[1].strip().split('/')
                        if len(times) >= 2:
                            print(f"  VPN Server latency: {times[1]} ms (avg)")

    return 0


def cmd_stats(args):
    """Show bandwidth statistics"""
    netns = "vpn"
    state_dir = Path(DEFAULT_STATE_DIR)
    stats_file = state_dir / "bandwidth_stats.json"

    print(f"MOLE v{__version__} - Bandwidth Statistics")
    print("=" * 40)

    result = run_in_netns(["wg", "show", "mole", "transfer"], netns, check=False)

    current_rx = 0
    current_tx = 0

    if result.returncode == 0 and result.stdout.strip():
        parts = result.stdout.strip().split()
        if len(parts) >= 3:
            current_rx = int(parts[1])
            current_tx = int(parts[2])

    stats = {"sessions": [], "total_rx": 0, "total_tx": 0}
    if stats_file.exists():
        try:
            stats = json.loads(stats_file.read_text())
        except Exception:
            pass

    def format_bytes(b):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(b) < 1024.0:
                return f"{b:.2f} {unit}"
            b /= 1024.0
        return f"{b:.2f} PB"

    print(f"\nCurrent session:")
    print(f"  Downloaded: {format_bytes(current_rx)}")
    print(f"  Uploaded:   {format_bytes(current_tx)}")

    total_rx = stats.get("total_rx", 0) + current_rx
    total_tx = stats.get("total_tx", 0) + current_tx

    print(f"\nAll time totals:")
    print(f"  Downloaded: {format_bytes(total_rx)}")
    print(f"  Uploaded:   {format_bytes(total_tx)}")
    print(f"  Total:      {format_bytes(total_rx + total_tx)}")

    if args.save:
        new_session = {
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "rx": current_rx,
            "tx": current_tx
        }
        stats["sessions"].append(new_session)
        stats["total_rx"] = stats.get("total_rx", 0) + current_rx
        stats["total_tx"] = stats.get("total_tx", 0) + current_tx
        stats["sessions"] = stats["sessions"][-100:]

        secure_write_file(stats_file, json.dumps(stats, indent=2))
        print(f"\nStats saved to {stats_file}")

    return 0


def cmd_qbittorrent(args):
    """Manage qBittorrent in the VPN namespace"""
    action = getattr(args, 'action', 'status')

    if action == 'setup':
        return _qbittorrent_setup(args)
    elif action == 'start':
        return _qbittorrent_control('start')
    elif action == 'stop':
        return _qbittorrent_control('stop')
    elif action == 'status':
        return _qbittorrent_status()
    elif action == 'enable':
        return _qbittorrent_control('enable')
    elif action == 'disable':
        return _qbittorrent_control('disable')
    elif action == 'passthrough':
        return _qbittorrent_passthrough(args)
    elif action == 'port':
        return _qbittorrent_port(args)
    else:
        print(f"Unknown action: {action}")
        return 1


def _qbittorrent_setup(args):
    """Setup qBittorrent to run in VPN namespace"""
    print(f"MOLE v{__version__} - qBittorrent Setup")
    print("=" * 50)

    if os.geteuid() != 0:
        print("Error: setup must be run as root (sudo mole qbittorrent setup)")
        return 1

    result = run_cmd(["which", "qbittorrent-nox"], check=False)
    if result.returncode != 0:
        print("Error: qbittorrent-nox is not installed")
        print("Install with: sudo apt install qbittorrent-nox")
        return 1

    config = Config()

    user = getattr(args, 'user', None) or config.qb_user
    if not user:
        import pwd
        for p in pwd.getpwall():
            if 1000 <= p.pw_uid < 65000 and p.pw_shell not in ('/bin/false', '/usr/sbin/nologin'):
                user = p.pw_name
                break

    port = getattr(args, 'port', None) or config.qb_port or 8080

    print(f"\nConfiguration:")
    print(f"  User: {user}")
    print(f"  Namespace: {config.netns}")
    print(f"  Web UI Port: {port}")

    config_file = Path(DEFAULT_CONFIG_FILE)
    if config_file.exists():
        content = config_file.read_text()
        updated = False

        if 'QB_PORT=' in content:
            new_content = re.sub(r'QB_PORT=\d*', f'QB_PORT={port}', content)
        else:
            new_content = content.rstrip() + f'\nQB_PORT={port}\n'
        if new_content != content:
            content = new_content
            updated = True

        if 'QB_USER=' in content:
            new_content = re.sub(r'QB_USER=.*', f'QB_USER={user}', content)
        else:
            new_content = content.rstrip() + f'\nQB_USER={user}\n'
        if new_content != content:
            content = new_content
            updated = True

        if updated:
            config_file.write_text(content)

    print("\nCreating wrapper scripts and service files...")
    _qbittorrent_setup_services(enable_passthrough=False, verbose=True)

    print("\nService created successfully!")
    print(f"\nAccess Web UI at: http://{config.veth_vpn_ip}:{port}")

    response = input("\nEnable and start qbittorrent-mole now? [Y/n]: ").strip().lower()
    if response not in ('n', 'no'):
        subprocess.run(["systemctl", "enable", "qbittorrent-mole"], check=False)
        result = subprocess.run(["systemctl", "is-active", "mole"], capture_output=True, text=True)
        if result.stdout.strip() == "active":
            subprocess.run(["systemctl", "start", "qbittorrent-mole"], check=False)
            print("qBittorrent started in VPN namespace!")

    return 0


def _qbittorrent_control(action):
    """Start/stop/enable/disable qbittorrent-mole service"""
    if os.geteuid() != 0:
        print(f"Error: {action} must be run as root")
        return 1

    service = "qbittorrent-mole"

    result = subprocess.run(["systemctl", "cat", service], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {service} service not found")
        print("Run 'sudo mole qbittorrent setup' first")
        return 1

    subprocess.run(["systemctl", action, service], capture_output=True, text=True)
    print(f"Service {action}ed successfully")

    return 0


def _qbittorrent_status():
    """Show qbittorrent-mole service status"""
    service = "qbittorrent-mole"

    print(f"MOLE v{__version__} - qBittorrent Status")
    print("=" * 50)

    result = subprocess.run(["systemctl", "cat", service], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"\nService '{service}' not configured")
        print("Run 'sudo mole qbittorrent setup' to create it")
        return 0

    result = subprocess.run(["systemctl", "is-active", service], capture_output=True, text=True)
    status = result.stdout.strip()
    print(f"\nService: {status}")

    result = subprocess.run(["systemctl", "is-enabled", service], capture_output=True, text=True)
    enabled = result.stdout.strip()
    print(f"Enabled: {enabled}")

    if status == "active":
        config = Config()
        qb_port = config.qb_port or 8080

        print(f"\nWeb UI: http://{config.veth_vpn_ip}:{qb_port}")

        pt_result = subprocess.run(
            ["systemctl", "is-active", "qbittorrent-passthrough"],
            capture_output=True, text=True
        )
        if pt_result.stdout.strip() == "active":
            print(f"        http://localhost:{qb_port} (passthrough active)")

    return 0


def _qbittorrent_passthrough(args):
    """Enable localhost passthrough for qBittorrent Web UI"""
    print(f"MOLE v{__version__} - qBittorrent Passthrough")
    print("=" * 50)

    if os.geteuid() != 0:
        print("Error: passthrough must be run as root")
        return 1

    result = subprocess.run(["which", "socat"], capture_output=True)
    if result.returncode != 0:
        print("Error: socat is not installed")
        print("Install with: sudo apt install socat")
        return 1

    config = Config()
    pt_path = Path("/etc/systemd/system/qbittorrent-passthrough.service")

    if pt_path.exists():
        print(f"Passthrough service already exists")
        result = subprocess.run(
            ["systemctl", "is-active", "qbittorrent-passthrough"],
            capture_output=True, text=True
        )
        if result.stdout.strip() != "active":
            response = input("Start it? [Y/n]: ").strip().lower()
            if response in ('', 'y', 'yes'):
                subprocess.run(["systemctl", "start", "qbittorrent-passthrough"], check=False)
        return 0

    print(f"Creating localhost passthrough for port {config.qb_port}...")
    _qbittorrent_setup_services(enable_passthrough=True, verbose=True)

    subprocess.run(["systemctl", "enable", "qbittorrent-passthrough"], check=False)
    subprocess.run(["systemctl", "start", "qbittorrent-passthrough"], check=False)

    print(f"\nPassthrough enabled!")
    print(f"qBittorrent Web UI: http://localhost:{config.qb_port}")

    return 0


def _qbittorrent_port(args):
    """Change qBittorrent Web UI port"""

    if os.geteuid() != 0:
        print("Error: port must be run as root")
        return 1

    new_port = getattr(args, 'port', None)
    if not new_port:
        print("Error: Please specify a port number")
        return 1

    print(f"MOLE v{__version__} - Change qBittorrent Port")
    print("=" * 50)
    print(f"\nChanging port to {new_port}...")

    config_file = Path(DEFAULT_CONFIG_FILE)
    if config_file.exists():
        content = config_file.read_text()

        if 'QB_PORT=' in content:
            new_content = re.sub(r'QB_PORT=\d+', f'QB_PORT={new_port}', content)
        else:
            new_content = re.sub(
                r'(QB_API_URL=http://[^:]+:)\d+',
                f'\\g<1>{new_port}',
                content
            )

        if new_content != content:
            config_file.write_text(new_content)
            print(f"  Updated: {config_file}")

    # Wrapper scripts read config at runtime, so just restart services
    print("\nRestarting services...")
    for service in ["qbittorrent-mole", "qbittorrent-passthrough"]:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True, text=True
        )
        if result.stdout.strip() == "active":
            subprocess.run(["systemctl", "restart", service], check=False)
            print(f"  Restarted: {service}")

    config = Config()
    print(f"\nqBittorrent port changed to {new_port}")
    print(f"Web UI: http://{config.veth_vpn_ip}:{new_port}")

    return 0


def cmd_run(args):
    """Run the VPN manager"""
    from .mole import Mole

    config_path = getattr(args, 'config', DEFAULT_CONFIG_FILE)
    mole = Mole(config_path)
    asyncio.run(mole.run())
    return 0


# ═══════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description=f"MOLE v{__version__} - Managed Obfuscated Link Environment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  init        Initialize directory structure and config
  status      Show current VPN status
  ip          Show current public IP through VPN
  regions     List available VPN regions/countries
  autoselect  Find fastest region/country with port forwarding
  speedtest   Test VPN connection speed
  stats       Show bandwidth statistics
  validate    Validate configuration file
  qbittorrent Manage qBittorrent in VPN namespace
  start       Start the VPN service
  restart     Force VPN reconnection
  stop        Stop the VPN service
  logs        Show service logs
  run         Run the VPN manager (used by systemd)

Examples:
  sudo mole init               # First-time setup
  mole validate                # Check config for errors
  sudo mole start              # Start VPN service
  sudo mole status             # Check VPN status
  mole ip                      # Show VPN public IP
  mole autoselect              # Find fastest region/country
  sudo mole qbittorrent setup  # Setup qBittorrent in VPN namespace
"""
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"MOLE v{__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # init command
    init_parser = subparsers.add_parser("init", help="Initialize MOLE")
    init_parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing files")

    # status command
    subparsers.add_parser("status", help="Show VPN status")

    # ip command
    subparsers.add_parser("ip", help="Show current public IP")

    # dns command
    dns_parser = subparsers.add_parser("dns", help="Test DNS over TLS functionality")
    dns_parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_FILE, help="Path to configuration file")
    dns_parser.add_argument("-n", "--namespace", action="store_true", help="Run tests from inside VPN namespace")

    # api-key command
    apikey_parser = subparsers.add_parser("api-key", help="Generate or show API key")
    apikey_parser.add_argument("action", nargs="?", choices=["generate", "show"], default="generate")
    apikey_parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_FILE)

    # regions command
    regions_parser = subparsers.add_parser("regions", help="List VPN regions/countries")
    regions_parser.add_argument("provider", nargs="?", default=None,
                                help="Provider (pia or proton). Auto-detects from config if not specified")
    regions_parser.add_argument("--pf", "--port-forward", dest="port_forward", action="store_true",
                                help="Only show regions/countries with port forwarding (P2P for ProtonVPN)")
    regions_parser.add_argument("-s", "--servers", action="store_true",
                                help="Show individual servers per region/country")
    regions_parser.add_argument("-t", "--tier", type=int, default=2, choices=[0, 1, 2],
                                help="ProtonVPN only: tier filter (0=free, 1=basic, 2=plus)")

    # autoselect command
    autoselect_parser = subparsers.add_parser("autoselect", help="Find fastest region/country")
    autoselect_parser.add_argument("-s", "--servers", action="store_true",
                                   help="Test individual servers instead of regions/countries")
    autoselect_parser.add_argument("-r", "--region", type=str, default=None,
                                   help="Filter to specific region (PIA) or country code (ProtonVPN)")
    autoselect_parser.add_argument("-t", "--tier", type=int, default=2, choices=[0, 1, 2],
                                   help="ProtonVPN only: tier filter (0=free, 1=basic, 2=plus)")

    # speedtest command
    subparsers.add_parser("speedtest", help="Test VPN speed")

    # stats command
    stats_parser = subparsers.add_parser("stats", help="Show bandwidth statistics")
    stats_parser.add_argument("--save", action="store_true")

    # validate command
    validate_parser = subparsers.add_parser("validate", help="Validate config file")
    validate_parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_FILE)

    # qbittorrent command
    qb_parser = subparsers.add_parser("qbittorrent", help="Manage qBittorrent in VPN namespace")
    qb_parser.add_argument("action", nargs="?", default="status",
                          choices=["setup", "start", "stop", "status", "enable", "disable", "passthrough", "port"])
    qb_parser.add_argument("--user", "-u", help="User to run qBittorrent as")
    qb_parser.add_argument("--port", "-p", type=int, default=None,
                          help="Web UI port (default: from config or 8080)")

    # start command
    subparsers.add_parser("start", help="Start the VPN service")

    # restart command
    restart_parser = subparsers.add_parser("restart", help="Force VPN reconnection")
    restart_parser.add_argument("--new-server", "-n", action="store_true",
                                help="Connect to a different server instead of the last used one")

    # stop command
    subparsers.add_parser("stop", help="Stop the VPN service")

    # logs command
    logs_parser = subparsers.add_parser("logs", help="Show service logs")
    logs_parser.add_argument("-f", "--follow", action="store_true")
    logs_parser.add_argument("-n", "--lines", type=int, default=50)

    # run command
    run_parser = subparsers.add_parser("run", help="Run VPN manager")
    run_parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_FILE)

    args = parser.parse_args()

    # Setup logging
    global log
    log = setup_logging(quiet=(args.command in ["status", "ip", "dns", "api-key", "regions", "stats"]))

    # Route to command
    commands = {
        "init": cmd_init,
        "status": cmd_status,
        "ip": cmd_ip,
        "dns": cmd_dns,
        "api-key": cmd_apikey,
        "regions": cmd_regions,
        "autoselect": cmd_autoselect,
        "speedtest": cmd_speedtest,
        "stats": cmd_stats,
        "validate": cmd_validate,
        "qbittorrent": cmd_qbittorrent,
        "start": cmd_start,
        "restart": cmd_restart,
        "stop": cmd_stop,
        "logs": cmd_logs,
        "run": cmd_run,
    }

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
