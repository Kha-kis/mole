"""
MOLE Network Management - Namespace, veth, and iptables utilities
"""

from pathlib import Path
from typing import TYPE_CHECKING

from .utils import log, run_cmd, run_in_netns

if TYPE_CHECKING:
    from .config import Config


def disable_ipv6_in_namespace(netns: str) -> None:
    """Disable IPv6 inside the namespace to prevent leaks.

    PIA does not support IPv6, so all IPv6 traffic must be blocked
    to prevent leaks outside the VPN tunnel.
    """
    log.info("Disabling IPv6 in namespace...")

    # Disable IPv6 on all interfaces in namespace
    run_in_netns([
        "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"
    ], netns, check=False)
    run_in_netns([
        "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"
    ], netns, check=False)

    # Also block IPv6 with ip6tables as defense in depth
    run_in_netns(["ip6tables", "-P", "INPUT", "DROP"], netns, check=False)
    run_in_netns(["ip6tables", "-P", "OUTPUT", "DROP"], netns, check=False)
    run_in_netns(["ip6tables", "-P", "FORWARD", "DROP"], netns, check=False)

    log.debug("IPv6 disabled in namespace")


def setup_namespace(config: "Config") -> None:
    """Setup network namespace and veth pair"""
    netns = config.netns

    # Create namespace if needed
    result = run_cmd(["ip", "netns", "list"], check=False)
    if netns not in result.stdout:
        log.info(f"Creating network namespace '{netns}'...")
        run_cmd(["ip", "netns", "add", netns])

    # Create veth pair if needed
    result = run_cmd(["ip", "link", "show", "veth-host"], check=False)
    if result.returncode != 0:
        log.info("Creating veth pair...")
        run_cmd(["ip", "link", "add", "veth-host", "type", "veth", "peer", "name", "veth-vpn"])
        run_cmd(["ip", "link", "set", "veth-vpn", "netns", netns])
        run_cmd(["ip", "addr", "add", f"{config.veth_host_ip}/24", "dev", "veth-host"])
        run_cmd(["ip", "link", "set", "veth-host", "up"])
        run_in_netns(["ip", "addr", "add", f"{config.veth_vpn_ip}/24", "dev", "veth-vpn"], netns)
        run_in_netns(["ip", "link", "set", "veth-vpn", "up"], netns)
        run_in_netns(["ip", "link", "set", "lo", "up"], netns)

    # Enable IP forwarding
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1")

    # Disable IPv6 in namespace to prevent leaks (PIA doesn't support IPv6)
    disable_ipv6_in_namespace(netns)

    # Setup NAT masquerade
    masq_check = run_cmd([
        "iptables", "-t", "nat", "-C", "POSTROUTING",
        "-s", "10.200.200.0/24", "-o", config.host_interface,
        "-j", "MASQUERADE"
    ], check=False)

    if masq_check.returncode != 0:
        run_cmd([
            "iptables", "-t", "nat", "-A", "POSTROUTING",
            "-s", "10.200.200.0/24", "-o", config.host_interface,
            "-j", "MASQUERADE"
        ])

    # Setup kill switch
    setup_killswitch(config)


def setup_killswitch(config: "Config") -> None:
    """Setup kill switch iptables rules inside the namespace.

    This function is idempotent - it always flushes and reapplies rules
    to ensure they match the current version's expected configuration.
    """
    netns = config.netns
    log.info("Setting up kill switch...")

    # Always flush and reapply rules (idempotent)
    # This ensures rules are always correct even after upgrades
    run_in_netns(["iptables", "-F", "OUTPUT"], netns, check=False)
    run_in_netns(["iptables", "-F", "INPUT"], netns, check=False)

    # Allow loopback
    run_in_netns([
        "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"
    ], netns, check=False)
    run_in_netns([
        "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"
    ], netns, check=False)

    # Allow traffic on veth-vpn ONLY to local subnet (10.200.200.0/24)
    # This prevents leaks - traffic cannot route to internet via veth
    # VPN server IP will be added separately by allow_vpn_server_ip()
    run_in_netns([
        "iptables", "-A", "OUTPUT", "-o", "veth-vpn",
        "-d", "10.200.200.0/24", "-j", "ACCEPT"
    ], netns, check=False)
    run_in_netns([
        "iptables", "-A", "INPUT", "-i", "veth-vpn",
        "-s", "10.200.200.0/24", "-j", "ACCEPT"
    ], netns, check=False)

    # Allow traffic on mole (WireGuard) interface
    run_in_netns([
        "iptables", "-A", "OUTPUT", "-o", "mole", "-j", "ACCEPT"
    ], netns, check=False)
    run_in_netns([
        "iptables", "-A", "INPUT", "-i", "mole", "-j", "ACCEPT"
    ], netns, check=False)

    # Allow established/related connections
    run_in_netns([
        "iptables", "-A", "INPUT", "-m", "state",
        "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
    ], netns, check=False)

    # Add marker rule
    run_in_netns([
        "iptables", "-A", "OUTPUT", "-m", "comment",
        "--comment", "mole-killswitch", "-j", "ACCEPT"
    ], netns, check=False)

    # Drop everything else (kill switch)
    run_in_netns([
        "iptables", "-A", "OUTPUT", "-j", "DROP"
    ], netns, check=False)
    run_in_netns([
        "iptables", "-A", "INPUT", "-j", "DROP"
    ], netns, check=False)

    log.info("Kill switch enabled - traffic blocked if VPN drops")


def allow_vpn_server_ip(config: "Config", server_ip: str, old_server_ip: str = None) -> None:
    """Add iptables rule to allow traffic to VPN server IP via veth-vpn.

    This must be called before connecting to the VPN so WireGuard UDP
    packets can reach the server through the veth pair.
    """
    netns = config.netns

    # Remove old server IP rule if switching servers
    if old_server_ip and old_server_ip != server_ip:
        log.debug(f"Removing old server IP rule: {old_server_ip}")
        run_in_netns([
            "iptables", "-D", "OUTPUT", "-o", "veth-vpn",
            "-d", old_server_ip, "-j", "ACCEPT"
        ], netns, check=False)

    # Check if rule already exists
    result = run_in_netns([
        "iptables", "-C", "OUTPUT", "-o", "veth-vpn",
        "-d", server_ip, "-j", "ACCEPT"
    ], netns, check=False)

    if result.returncode != 0:
        # Rule doesn't exist, add it
        # Insert after local subnet rule but before the DROP rule
        log.info(f"Allowing VPN server IP: {server_ip}")
        run_in_netns([
            "iptables", "-I", "OUTPUT", "3", "-o", "veth-vpn",
            "-d", server_ip, "-j", "ACCEPT"
        ], netns, check=False)


def cleanup_namespace(netns: str) -> None:
    """Cleanup network namespace and related interfaces"""
    log.info(f"Cleaning up namespace '{netns}'...")

    # Delete veth pair (this automatically removes both ends)
    run_cmd(["ip", "link", "del", "veth-host"], check=False)

    # Delete namespace
    run_cmd(["ip", "netns", "del", netns], check=False)


def connect_vpn(config: "Config", server_ip: str, server_vip: str, old_server_ip: str = None) -> bool:
    """Establish VPN connection"""
    log.info("Connecting VPN...")

    netns = config.netns

    # Bring down existing connection
    run_in_netns(["wg-quick", "down", "mole"], netns, check=False)

    # Allow traffic to VPN server IP through the kill switch
    allow_vpn_server_ip(config, server_ip, old_server_ip)

    # Update routes
    if old_server_ip:
        run_in_netns(["ip", "route", "del", old_server_ip, "via", config.veth_host_ip], netns, check=False)

    run_in_netns([
        "ip", "route", "add", server_ip,
        "via", config.veth_host_ip, "dev", "veth-vpn"
    ], netns, check=False)

    # Bring up WireGuard
    from .utils import sanitize_for_log
    result = run_in_netns(["wg-quick", "up", config.wg_conf], netns, check=False)
    if result.returncode != 0:
        log.error(f"Failed to bring up WireGuard: {sanitize_for_log(result.stderr)}")
        return False

    # Verify connection
    result = run_in_netns(["ping", "-c", "1", "-W", "5", server_vip], netns, check=False)
    if result.returncode != 0:
        log.warning("VPN connectivity check failed, but continuing...")

    log.info("VPN connected")
    return True


def disconnect_vpn(config: "Config") -> None:
    """Disconnect VPN"""
    log.info("Disconnecting VPN...")
    run_in_netns(["wg-quick", "down", config.wg_conf], config.netns, check=False)
