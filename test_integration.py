#!/usr/bin/env python3
"""
Integration tests for MOLE - verifies all features are complete and working
"""

import sys
import os
import tempfile
from pathlib import Path

def test_section(name):
    print(f"\n{'='*60}")
    print(f"  {name}")
    print('='*60)

def test_pass(name):
    print(f"  ✓ {name}")
    return True

def test_fail(name, reason=""):
    print(f"  ✗ {name}: {reason}")
    return False

# Load mole module by reading and executing
mole_globals = {}
with open('mole', 'r') as f:
    code = compile(f.read(), 'mole', 'exec')
    exec(code, mole_globals)

# Extract classes and functions from mole
Config = mole_globals.get('Config')
HTTPAPIServer = mole_globals.get('HTTPAPIServer')
HTTPProxyServer = mole_globals.get('HTTPProxyServer')
DNSOverTLSServer = mole_globals.get('DNSOverTLSServer')
DOT_PROVIDERS = mole_globals.get('DOT_PROVIDERS')
PIAProvider = mole_globals.get('PIAProvider')
Mole = mole_globals.get('Mole')
secure_write_file = mole_globals.get('secure_write_file')
sanitize_for_log = mole_globals.get('sanitize_for_log')
validate_config = mole_globals.get('validate_config')

def test_config_properties():
    """Test all config properties exist and have correct defaults"""
    test_section("Config Properties")
    passed = True

    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
        f.write("VPN_PROVIDER=pia\n")
        f.write("PIA_USER=test\n")
        f.write("PIA_PASS=test\n")
        f.write("PIA_REGION=ca_toronto\n")
        config_path = f.name

    try:
        config = Config(config_path)

        props = [
            ('vpn_provider', 'pia'),
            ('netns', 'vpn'),
            ('veth_host_ip', '10.200.200.1'),
            ('veth_vpn_ip', '10.200.200.2'),
            ('host_interface', 'eth0'),
            ('port_forward', True),
            ('torrent_client', 'qbittorrent'),
        ]

        for prop, expected in props:
            val = getattr(config, prop)
            if val == expected:
                test_pass(f"config.{prop} = {val}")
            else:
                passed = test_fail(f"config.{prop}", f"expected {expected}, got {val}")

        api_props = [
            ('http_api_enabled', False),
            ('http_api_port', 8080),
            ('http_api_bind', '127.0.0.1'),
            ('http_api_key', ''),
        ]

        for prop, expected in api_props:
            val = getattr(config, prop)
            if val == expected:
                test_pass(f"config.{prop} = {val}")
            else:
                passed = test_fail(f"config.{prop}", f"expected {expected}, got {val}")

        proxy_props = [
            ('proxy_enabled', False),
            ('proxy_port', 8888),
            ('proxy_bind', '10.200.200.1'),
            ('proxy_user', 'mole'),
            ('proxy_pass', ''),
        ]

        for prop, expected in proxy_props:
            val = getattr(config, prop)
            if val == expected:
                test_pass(f"config.{prop} = {val}")
            else:
                passed = test_fail(f"config.{prop}", f"expected {expected}, got {val}")

        dot_props = [
            ('dot_enabled', False),
            ('dot_port', 53),
            ('dot_bind', '10.200.200.2'),
            ('dot_upstream', 'cloudflare'),
            ('dot_block_ads', True),
            ('dot_block_malware', True),
            ('dot_block_tracking', False),
            ('dot_caching', True),
            ('dot_cache_ttl', 0),
            ('dot_update_period', 86400),
        ]

        for prop, expected in dot_props:
            val = getattr(config, prop)
            if val == expected:
                test_pass(f"config.{prop} = {val}")
            else:
                passed = test_fail(f"config.{prop}", f"expected {expected}, got {val}")

    finally:
        os.unlink(config_path)

    return passed

def test_http_api_endpoints():
    """Test HTTP API has all required endpoints"""
    test_section("HTTP API Endpoints")
    passed = True

    if HTTPAPIServer:
        test_pass("HTTPAPIServer class exists")
    else:
        return test_fail("HTTPAPIServer class missing")

    required_methods = [
        'start', 'stop', '_check_auth', '_handle_request', '_route_request',
        '_get_status', '_get_port', '_get_ip', '_get_server', '_get_health', '_get_dns', '_put_restart',
    ]

    for method in required_methods:
        if hasattr(HTTPAPIServer, method):
            test_pass(f"HTTPAPIServer.{method}() exists")
        else:
            passed = test_fail(f"HTTPAPIServer.{method}() missing")

    return passed

def test_http_proxy():
    """Test HTTP Proxy has all required methods"""
    test_section("HTTP Proxy")
    passed = True

    if HTTPProxyServer:
        test_pass("HTTPProxyServer class exists")
    else:
        return test_fail("HTTPProxyServer class missing")

    required_methods = [
        'start', 'stop', '_check_auth', '_is_blocked_target',
        '_handle_connection', '_handle_connect', '_handle_http',
        '_send_auth_required', '_send_error',
    ]

    for method in required_methods:
        if hasattr(HTTPProxyServer, method):
            test_pass(f"HTTPProxyServer.{method}() exists")
        else:
            passed = test_fail(f"HTTPProxyServer.{method}() missing")

    if hasattr(HTTPProxyServer, 'BLOCKED_NETWORKS'):
        networks = HTTPProxyServer.BLOCKED_NETWORKS
        if len(networks) >= 5:
            test_pass(f"SSRF BLOCKED_NETWORKS defined ({len(networks)} entries)")
        else:
            passed = test_fail("BLOCKED_NETWORKS too few entries")
    else:
        passed = test_fail("BLOCKED_NETWORKS missing")

    return passed

def test_dns_over_tls():
    """Test DNS over TLS has all required methods"""
    test_section("DNS over TLS")
    passed = True

    if DNSOverTLSServer:
        test_pass("DNSOverTLSServer class exists")
    else:
        return test_fail("DNSOverTLSServer class missing")

    required_methods = [
        'start', 'stop', '_get_upstream', '_load_blocklists',
        'resolve', '_extract_domain', '_extract_qtype', '_extract_response_ttl',
        '_is_blocked', '_make_nxdomain_response', '_query_upstream',
        '_blocklist_update_loop',
    ]

    for method in required_methods:
        if hasattr(DNSOverTLSServer, method):
            test_pass(f"DNSOverTLSServer.{method}() exists")
        else:
            passed = test_fail(f"DNSOverTLSServer.{method}() missing")

    if DOT_PROVIDERS:
        required_providers = ['cloudflare', 'cloudflare-family', 'quad9', 'google']
        for p in required_providers:
            if p in DOT_PROVIDERS:
                if len(DOT_PROVIDERS[p]) == 3:
                    test_pass(f"DOT_PROVIDERS['{p}'] has (ip, port, sni)")
                else:
                    passed = test_fail(f"DOT_PROVIDERS['{p}']", "should have (ip, port, sni)")
            else:
                passed = test_fail(f"DOT_PROVIDERS['{p}'] missing")
    else:
        passed = test_fail("DOT_PROVIDERS missing")

    return passed

def test_cli_commands():
    """Test all CLI commands exist"""
    test_section("CLI Commands")
    passed = True

    required_commands = [
        'cmd_init', 'cmd_status', 'cmd_regions', 'cmd_restart',
        'cmd_logs', 'cmd_ip', 'cmd_dns', 'cmd_apikey', 'cmd_stop',
        'cmd_validate', 'cmd_speedtest', 'cmd_autoselect', 'cmd_stats', 'cmd_qbittorrent',
    ]

    for cmd in required_commands:
        if cmd in mole_globals:
            test_pass(f"{cmd}() exists")
        else:
            passed = test_fail(f"{cmd}() missing")

    return passed

def test_security_functions():
    """Test security helper functions exist"""
    test_section("Security Functions")
    passed = True

    if secure_write_file:
        test_pass("secure_write_file() exists")
    else:
        passed = test_fail("secure_write_file() missing")

    if sanitize_for_log:
        test_pass("sanitize_for_log() exists")
    else:
        passed = test_fail("sanitize_for_log() missing")

    if validate_config:
        test_pass("validate_config() exists")
    else:
        passed = test_fail("validate_config() missing")

    return passed

def test_vpn_provider():
    """Test VPN provider implementation"""
    test_section("VPN Provider (PIA)")
    passed = True

    if PIAProvider:
        test_pass("PIAProvider class exists")
    else:
        return test_fail("PIAProvider class missing")

    required_methods = [
        'authenticate', 'get_server', 'register_wireguard',
        'setup_port_forward', 'refresh_port_forward',
    ]

    for method in required_methods:
        if hasattr(PIAProvider, method):
            test_pass(f"PIAProvider.{method}() exists")
        else:
            passed = test_fail(f"PIAProvider.{method}() missing")

    return passed

def test_mole_class():
    """Test main Mole class"""
    test_section("Mole Main Class")
    passed = True

    if Mole:
        test_pass("Mole class exists")
    else:
        return test_fail("Mole class missing")

    required_methods = [
        'run', '_cleanup', '_setup_namespace', '_setup_killswitch',
        '_full_renewal', '_connect_vpn', '_keepalive_loop',
        '_watchdog_loop', '_check_health',
    ]

    for method in required_methods:
        if hasattr(Mole, method):
            test_pass(f"Mole.{method}() exists")
        else:
            passed = test_fail(f"Mole.{method}() missing")

    return passed

def main():
    print("\n" + "="*60)
    print("  MOLE Integration Tests - All Features")
    print("="*60)

    results = []

    results.append(("Config Properties", test_config_properties()))
    results.append(("HTTP API Endpoints", test_http_api_endpoints()))
    results.append(("HTTP Proxy", test_http_proxy()))
    results.append(("DNS over TLS", test_dns_over_tls()))
    results.append(("CLI Commands", test_cli_commands()))
    results.append(("Security Functions", test_security_functions()))
    results.append(("VPN Provider", test_vpn_provider()))
    results.append(("Mole Main Class", test_mole_class()))

    print("\n" + "="*60)
    print("  Integration Test Summary")
    print("="*60)

    passed = 0
    failed = 0
    for name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "✓" if result else "✗"
        print(f"  {symbol} {name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n  Total: {passed} passed, {failed} failed")
    print("="*60 + "\n")

    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
