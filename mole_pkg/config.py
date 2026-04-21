"""
MOLE Configuration Management
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Tuple

from .constants import (
    DEFAULT_CONFIG_FILE,
    DEFAULT_CONFIG_DIR,
    DEFAULT_STATE_DIR,
    DEFAULT_WG_CONF,
)


def load_config(config_path: str = DEFAULT_CONFIG_FILE) -> Dict[str, str]:
    """Load configuration from config file and environment variables"""
    config = {}

    # Load from config file
    config_file = Path(config_path)
    if config_file.exists():
        with open(config_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, _, value = line.partition('=')
                    config[key.strip()] = value.strip()

    # Environment variables override config file
    for key in config.keys():
        if key in os.environ:
            config[key] = os.environ[key]

    # Also check for any MOLE_ prefixed env vars
    for key, value in os.environ.items():
        if key.startswith('MOLE_'):
            config[key[5:]] = value  # Strip MOLE_ prefix

    return config


class Config:
    """Application configuration"""
    def __init__(self, config_path: str = DEFAULT_CONFIG_FILE):
        self._data = load_config(config_path)

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def get_int(self, key: str, default: int = 0) -> int:
        try:
            return int(self._data.get(key, default))
        except (ValueError, TypeError):
            return default

    @property
    def vpn_provider(self) -> str:
        return self.get('VPN_PROVIDER', 'pia')

    @property
    def netns(self) -> str:
        return self.get('NETNS_NAME', 'vpn')

    @property
    def veth_host_ip(self) -> str:
        return self.get('VETH_HOST_IP', '10.200.200.1')

    @property
    def veth_vpn_ip(self) -> str:
        return self.get('VETH_VPN_IP', '10.200.200.2')

    @property
    def host_interface(self) -> str:
        return self.get('HOST_INTERFACE', 'eth0')

    @property
    def wg_conf(self) -> str:
        return self.get('WG_CONF', DEFAULT_WG_CONF)

    @property
    def config_dir(self) -> str:
        return self.get('CONFIG_DIR', DEFAULT_CONFIG_DIR)

    @property
    def state_dir(self) -> str:
        return self.get('STATE_DIR', DEFAULT_STATE_DIR)

    @property
    def port_forward(self) -> bool:
        val = self.get('PORT_FORWARD', 'true').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def torrent_client(self) -> str:
        return self.get('TORRENT_CLIENT', 'qbittorrent')

    @property
    def qb_api_url(self) -> str:
        # Build URL from components if QB_PORT is set, otherwise use legacy QB_API_URL
        port = self.get('QB_PORT', '')
        if port:
            return f"http://{self.veth_vpn_ip}:{port}/api/v2/app"
        return self.get('QB_API_URL', 'http://localhost:8080/api/v2/app')

    @property
    def qb_port(self) -> int:
        # Get from QB_PORT, or extract from QB_API_URL for backwards compatibility
        port = self.get('QB_PORT', '')
        if port:
            try:
                return int(port)
            except ValueError:
                pass  # Fall through to try QB_API_URL or default
        # Try to extract from QB_API_URL
        url = self.get('QB_API_URL', '')
        match = re.search(r':(\d+)(?:/|$)', url)
        if match:
            return int(match.group(1))
        return 8080

    @property
    def qb_user(self) -> str:
        return self.get('QB_USER', '')

    @property
    def renewal_interval(self) -> int:
        return self.get_int('RENEWAL_INTERVAL', 72000)

    @property
    def keepalive_interval(self) -> int:
        return self.get_int('KEEPALIVE_INTERVAL', 900)

    @property
    def watchdog_interval(self) -> int:
        return self.get_int('WATCHDOG_INTERVAL', 60)

    @property
    def watchdog_max_failures(self) -> int:
        return self.get_int('WATCHDOG_MAX_FAILURES', 3)

    # HTTP Control API
    @property
    def http_api_enabled(self) -> bool:
        val = self.get('HTTP_API_ENABLED', 'false').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def http_api_port(self) -> int:
        return self.get_int('HTTP_API_PORT', 8080)

    @property
    def http_api_bind(self) -> str:
        # API runs IN namespace, 0.0.0.0 makes it accessible from host via veth
        return self.get('HTTP_API_BIND', '0.0.0.0')

    @property
    def http_api_key(self) -> str:
        return self.get('HTTP_API_KEY', '')

    # HTTP Proxy
    @property
    def proxy_enabled(self) -> bool:
        val = self.get('PROXY_ENABLED', 'false').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def proxy_port(self) -> int:
        return self.get_int('PROXY_PORT', 8888)

    @property
    def proxy_bind(self) -> str:
        # Proxy runs IN namespace, 0.0.0.0 makes it accessible from host via veth
        return self.get('PROXY_BIND', '0.0.0.0')

    @property
    def proxy_user(self) -> str:
        return self.get('PROXY_USER', 'mole')

    @property
    def proxy_pass(self) -> str:
        return self.get('PROXY_PASS', '')

    # DNS over TLS
    @property
    def dot_enabled(self) -> bool:
        val = self.get('DOT_ENABLED', 'false').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def dot_port(self) -> int:
        return self.get_int('DOT_PORT', 53)

    @property
    def dot_bind(self) -> str:
        # DNS server runs IN namespace, serves apps in namespace
        # 127.0.0.1 for namespace-local, 0.0.0.0 to also serve host via veth
        return self.get('DOT_BIND', '127.0.0.1')

    @property
    def dot_upstream(self) -> str:
        return self.get('DOT_UPSTREAM', 'cloudflare')

    @property
    def dot_custom_server(self) -> str:
        return self.get('DOT_CUSTOM_SERVER', '')

    @property
    def dot_block_ads(self) -> bool:
        val = self.get('DOT_BLOCK_ADS', 'true').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def dot_block_malware(self) -> bool:
        val = self.get('DOT_BLOCK_MALWARE', 'true').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def dot_block_tracking(self) -> bool:
        val = self.get('DOT_BLOCK_TRACKING', 'false').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def dot_caching(self) -> bool:
        """Enable DNS response caching for improved performance"""
        val = self.get('DOT_CACHING', 'true').lower()
        return val in ('true', '1', 'yes', 'on')

    @property
    def dot_cache_ttl(self) -> int:
        """Maximum cache TTL in seconds (0 = use response TTL)"""
        return self.get_int('DOT_CACHE_TTL', 0)

    @property
    def dot_update_period(self) -> int:
        """Blocklist update period in seconds (0 = disabled, default 24h)"""
        val = self.get('DOT_UPDATE_PERIOD', '86400')  # 24 hours
        # Parse time strings like "24h", "1d", "30m"
        val = val.strip().lower()
        if val.endswith('h'):
            return int(val[:-1]) * 3600
        elif val.endswith('d'):
            return int(val[:-1]) * 86400
        elif val.endswith('m'):
            return int(val[:-1]) * 60
        return int(val)

    @property
    def dot_upstreams(self) -> List[str]:
        """Ordered list of upstream DNS providers. Accepts the same values as
        DOT_UPSTREAM (named preset or 'custom') as a comma-separated list.
        Rotated on failover."""
        raw = self.get('DOT_UPSTREAM', 'cloudflare')
        return [u.strip() for u in raw.split(',') if u.strip()]

    @property
    def dot_pool_size(self) -> int:
        """Persistent TLS connections per upstream. Higher = more parallelism
        absorbed before queueing; 2 is plenty for most workloads."""
        return max(1, self.get_int('DOT_POOL_SIZE', 2))

    @property
    def dot_query_timeout(self) -> float:
        """Per-attempt upstream query timeout, seconds. Applies to the whole
        send+receive cycle (not per-stage)."""
        try:
            return max(0.1, float(self.get('DOT_QUERY_TIMEOUT', '2.0')))
        except (ValueError, TypeError):
            return 2.0

    @property
    def dot_query_retries(self) -> int:
        """Retries per upstream before failing over to the next upstream.
        Total attempts = (retries + 1) * len(dot_upstreams)."""
        return max(0, self.get_int('DOT_QUERY_RETRIES', 2))

    @property
    def dot_retry_backoff_ms(self) -> int:
        """Bounded delay between retries, milliseconds."""
        return max(0, self.get_int('DOT_RETRY_BACKOFF_MS', 200))

    # Hooks
    @property
    def post_connect_hook(self) -> str:
        """Script to run after VPN connects (runs in namespace)"""
        return self.get('POST_CONNECT_HOOK', '')

    @property
    def post_disconnect_hook(self) -> str:
        """Script to run before VPN disconnects"""
        return self.get('POST_DISCONNECT_HOOK', '')


def validate_config(config_path: str = DEFAULT_CONFIG_FILE) -> Tuple[bool, List[str]]:
    """Validate configuration file and return (is_valid, list of errors/warnings)"""
    errors = []
    warnings = []

    config_file = Path(config_path)

    # Check if config file exists
    if not config_file.exists():
        errors.append(f"Config file not found: {config_path}")
        return False, errors

    # Load config
    try:
        config = Config(config_path)
    except Exception as e:
        errors.append(f"Failed to parse config: {e}")
        return False, errors

    # Required fields for PIA
    if config.vpn_provider.lower() == 'pia':
        if not config.get('PIA_USER') or config.get('PIA_USER') == 'your_username':
            errors.append("PIA_USER is not set or still has default value")
        if not config.get('PIA_PASS') or config.get('PIA_PASS') == 'your_password':
            errors.append("PIA_PASS is not set or still has default value")

        # Validate credentials don't contain dangerous characters
        for key in ['PIA_USER', 'PIA_PASS']:
            value = config.get(key, '')
            if value:
                # Check for control characters, null bytes, or newlines
                if any(ord(c) < 32 or ord(c) == 127 for c in value):
                    errors.append(f"{key} contains invalid control characters")
                # Check for overly long credentials (prevent DoS/buffer issues)
                if len(value) > 256:
                    errors.append(f"{key} is too long (max 256 characters)")

        # Validate PIA_REGION (supports comma-separated fallback list)
        region_str = config.get('PIA_REGION', '')
        if not region_str:
            warnings.append("PIA_REGION not set - will auto-detect on first run")
        else:
            regions = [r.strip() for r in region_str.split(',') if r.strip()]
            if not regions:
                warnings.append("PIA_REGION is empty - will auto-detect on first run")
            elif len(regions) > 1:
                warnings.append(f"Using fallback regions: {', '.join(regions)}")

        # Validate PIA_SERVER if set (optional)
        server_hostname = config.get('PIA_SERVER', '').strip()
        if server_hostname:
            warnings.append(f"Using specific server: {server_hostname}")

        # Validate PIA_DIP_TOKEN if set (optional)
        dip_token = config.get('PIA_DIP_TOKEN', '').strip()
        if dip_token:
            warnings.append("Using Dedicated IP token")
            if not dip_token.startswith('dip_'):
                warnings.append("PIA_DIP_TOKEN should start with 'dip_' - verify token format")

        # Validate PIA_MAX_LATENCY if set (optional)
        max_latency = config.get('PIA_MAX_LATENCY', '').strip()
        if max_latency:
            try:
                lat_val = int(max_latency)
                if lat_val < 0:
                    errors.append("PIA_MAX_LATENCY must be a positive number")
                elif lat_val > 0 and lat_val < 10:
                    warnings.append(f"PIA_MAX_LATENCY ({lat_val}ms) is very low - may exclude all servers")
                else:
                    warnings.append(f"Server selection limited to <{lat_val}ms latency")
            except ValueError:
                errors.append(f"PIA_MAX_LATENCY must be a number, got: {max_latency}")

        # Check CA cert exists
        ca_cert = Path(config.config_dir) / "providers" / "pia-ca.crt"
        if not ca_cert.exists():
            errors.append(f"PIA CA certificate not found: {ca_cert}")

    # Required fields for ProtonVPN
    elif config.vpn_provider.lower() in ('proton', 'protonvpn'):
        if not config.get('PROTON_USER'):
            errors.append("PROTON_USER is not set")
        if not config.get('PROTON_PASS'):
            errors.append("PROTON_PASS is not set")

        # Validate credentials don't contain dangerous characters
        for key in ['PROTON_USER', 'PROTON_PASS']:
            value = config.get(key, '')
            if value:
                if any(ord(c) < 32 or ord(c) == 127 for c in value):
                    errors.append(f"{key} contains invalid control characters")
                if len(value) > 256:
                    errors.append(f"{key} is too long (max 256 characters)")

        # Validate PROTON_COUNTRY if set (supports comma-separated fallback list)
        country_str = config.get('PROTON_COUNTRY', '').strip()
        if country_str:
            countries = [c.strip().upper() for c in country_str.split(',') if c.strip()]
            if not countries:
                warnings.append("PROTON_COUNTRY is empty")
            else:
                for country in countries:
                    if len(country) != 2:
                        warnings.append(f"PROTON_COUNTRY should be 2-letter codes (e.g., US, CH), got: {country}")
                        break
                else:
                    if len(countries) > 1:
                        warnings.append(f"Using fallback countries: {', '.join(countries)}")
                    else:
                        warnings.append(f"Using country filter: {countries[0]}")

        # Validate PROTON_SERVER if set
        server = config.get('PROTON_SERVER', '').strip()
        if server:
            warnings.append(f"Using specific server: {server}")

        # Validate PROTON_MAX_LATENCY if set
        max_latency = config.get('PROTON_MAX_LATENCY', '').strip()
        if max_latency:
            try:
                lat_val = int(max_latency)
                if lat_val < 0:
                    errors.append("PROTON_MAX_LATENCY must be a positive number")
                elif lat_val > 0 and lat_val < 10:
                    warnings.append(f"PROTON_MAX_LATENCY ({lat_val}ms) is very low - may exclude all servers")
                else:
                    warnings.append(f"Server selection limited to <{lat_val}ms latency")
            except ValueError:
                errors.append(f"PROTON_MAX_LATENCY must be a number, got: {max_latency}")

        # Validate PROTON_NETSHIELD if set
        netshield = config.get('PROTON_NETSHIELD', '').strip()
        if netshield:
            try:
                ns_val = int(netshield)
                if ns_val not in (0, 1, 2):
                    errors.append("PROTON_NETSHIELD must be 0 (off), 1 (block malware), or 2 (block malware+ads+trackers)")
                elif ns_val == 1:
                    warnings.append("NetShield enabled: blocking malware")
                elif ns_val == 2:
                    warnings.append("NetShield enabled: blocking malware, ads, and trackers")
            except ValueError:
                errors.append(f"PROTON_NETSHIELD must be 0, 1, or 2, got: {netshield}")

        # Validate tier
        tier = config.get('PROTON_TIER', '').strip()
        if tier:
            try:
                tier_val = int(tier)
                if tier_val not in (0, 1, 2):
                    warnings.append(f"PROTON_TIER should be 0 (free), 1 (basic), or 2 (plus)")
            except ValueError:
                errors.append(f"PROTON_TIER must be a number (0, 1, or 2), got: {tier}")

        # Check for port forwarding requirements
        if config.port_forward:
            tier_val = int(config.get('PROTON_TIER', '2'))
            if tier_val < 2:
                warnings.append("Port forwarding requires ProtonVPN Plus plan (tier 2)")

            # Check natpmpc is installed
            result = subprocess.run(["which", "natpmpc"], capture_output=True, text=True)
            if result.returncode != 0:
                errors.append("natpmpc not installed (required for port forwarding). Install with: apt install natpmpc")

        # Check proton-client is installed
        try:
            import proton.api
        except ImportError:
            errors.append("proton-client not installed. Install with: pip install proton-client")

    # Validate network settings
    host_iface = config.host_interface
    result = subprocess.run(["ip", "link", "show", host_iface],
                          capture_output=True, text=True)
    if result.returncode != 0:
        warnings.append(f"HOST_INTERFACE '{host_iface}' not found (may be OK if using different name)")

    # Validate IP addresses
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

    for key in ['VETH_HOST_IP', 'VETH_VPN_IP']:
        value = config.get(key, '')
        if value and not ip_pattern.match(value):
            errors.append(f"{key} is not a valid IP address: {value}")

    # Validate timing values
    if config.renewal_interval < 3600:
        warnings.append(f"RENEWAL_INTERVAL ({config.renewal_interval}s) is less than 1 hour")
    if config.keepalive_interval < 30:
        warnings.append(f"KEEPALIVE_INTERVAL ({config.keepalive_interval}s) is less than 30 seconds")

    # Provider-specific keepalive requirements
    provider = config.vpn_provider.lower()
    if provider == 'pia':
        if config.keepalive_interval > 900:
            warnings.append(f"KEEPALIVE_INTERVAL ({config.keepalive_interval}s) exceeds PIA's 15-minute requirement")
    elif provider in ('proton', 'protonvpn'):
        if config.port_forward and config.keepalive_interval > 45:
            warnings.append(f"KEEPALIVE_INTERVAL ({config.keepalive_interval}s) exceeds ProtonVPN NAT-PMP's ~60s timeout")
            warnings.append("Consider setting KEEPALIVE_INTERVAL=45 for ProtonVPN with port forwarding")

    # Validate torrent client settings
    if config.torrent_client.lower() == 'qbittorrent':
        qb_url = config.qb_api_url
        if not qb_url.startswith('http'):
            errors.append(f"QB_API_URL must start with http:// or https://")

    # Check provider is supported
    supported_providers = ['pia', 'proton', 'protonvpn']
    if config.vpn_provider.lower() not in supported_providers:
        errors.append(f"VPN_PROVIDER '{config.vpn_provider}' is not supported. Use: pia, proton")

    # Check torrent client is supported
    supported_clients = ['qbittorrent', 'none', 'disabled', '']
    if config.torrent_client.lower() not in supported_clients:
        errors.append(f"TORRENT_CLIENT '{config.torrent_client}' is not supported. Use: qbittorrent or none")

    # Check port forwarding / torrent client combination
    if not config.port_forward:
        if config.torrent_client.lower() not in ('none', 'disabled', ''):
            warnings.append(f"TORRENT_CLIENT is set but PORT_FORWARD is disabled - port won't be updated")
    else:
        if config.torrent_client.lower() in ('none', 'disabled', ''):
            warnings.append(f"PORT_FORWARD is enabled but TORRENT_CLIENT is disabled - port will be forwarded but not used")

    # Check HTTP API security configuration
    if config.http_api_enabled:
        bind_addr = config.http_api_bind
        if not config.http_api_key and bind_addr not in ('127.0.0.1', 'localhost', '::1'):
            warnings.append(f"SECURITY: HTTP API bound to '{bind_addr}' without authentication - set HTTP_API_KEY")

    # Check HTTP Proxy authentication
    if config.proxy_enabled and not config.proxy_pass:
        errors.append("PROXY_ENABLED is true but PROXY_PASS is not set - proxy requires authentication")

    all_issues = errors + [f"Warning: {w}" for w in warnings]
    return len(errors) == 0, all_issues
