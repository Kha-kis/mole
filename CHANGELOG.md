# Changelog

All notable changes to MOLE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`QB_PASSTHROUGH_MODE`**: Select `socat` (backward-compatible default) or an isolated, HTTP-aware `nginx` relay for qBittorrent Web API access. Nginx mode prevents Arr clients from reusing connections beyond qBittorrent's upstream HTTP keep-alive lifetime.
- **`QB_PASSTHROUGH_BIND`**: Configurable bind address for the qBittorrent passthrough listener (default: `127.0.0.1`). Set to your Docker bridge gateway (e.g. `172.24.0.1`) to allow containers on that bridge to connect directly.
- **TCP keepalive on socat passthrough**: Both sides of the raw TCP relay set `keepalive,keepidle=30,keepintvl=10,keepcnt=3` to detect dead peers. TCP keepalive does not resolve qBittorrent's shorter HTTP connection lifetime; use `QB_PASSTHROUGH_MODE=nginx` for that case.

## [0.4.0] - 2026-01-16

### Added
- **ProtonVPN Support**: Full WireGuard-based ProtonVPN provider with NAT-PMP port forwarding
- **Multi-Region Fallback**: Comma-separated region/country list for automatic failover
- **Latency-Based Server Selection**: `autoselect` command tests server latency with concurrent pings
- **Server Stickiness**: Remembers and prefers last working server (configurable)
- **NetShield Integration**: ProtonVPN DNS filtering for malware, ads, and trackers
- **Speed Testing**: `speedtest` command to test VPN connection throughput
- **Bandwidth Statistics**: `stats` command to track upload/download usage over time
- **HTTP Control API**: REST API for querying and controlling VPN state
- **HTTP Proxy**: Authenticated proxy to route traffic through VPN namespace
- **DNS over TLS**: Encrypted DNS with caching and auto-updating blocklists
- **qBittorrent Integration**: Automatic setup and management in VPN namespace
- **Localhost Passthrough**: `qbittorrent passthrough` for localhost access to Web UI
- **API Key Management**: `api-key generate` and `api-key show` commands
- **Start Command**: Added `mole start` for consistency with stop/restart

### Changed
- Replaced `apply` command with runtime config wrapper scripts
- qBittorrent services now read config at runtime (no regeneration needed)
- Improved help text for provider-specific CLI options
- `--port` argument no longer overrides config file setting

### Fixed
- qBittorrent status now reads port from config instead of parsing service files
- ProtonVPN API authentication using persistent session
- Rate limiting with exponential backoff for both providers
- Port forwarding persistence across restarts (60-day for PIA, session-based for ProtonVPN)
- Health check now works correctly for both PIA and ProtonVPN
- Invalid port numbers now properly validated (1-65535 range)
- Config integer parsing now handles invalid values gracefully
- Race condition in restart trigger file handling

### Security
- Network namespace isolation for all VPN traffic
- Kill switch blocks traffic if VPN connection drops
- IPv6 disabled in namespace to prevent leaks
- DNS queries forced through VPN tunnel
- SSRF protection in HTTP proxy (blocks internal IP ranges)
- Config files and WireGuard config written with 0600 permissions
- Credentials masked in logs
- Proxy password passed via environment variable (not visible in process list)

## [0.3.0] - 2026-01-01

### Added
- Initial PIA (Private Internet Access) provider support
- WireGuard-based VPN connections
- Automatic token renewal
- Port forwarding with 60-day persistence
- Dedicated IP support for PIA
- Basic CLI with init, status, restart, stop, logs commands
- Systemd service integration
- Configuration validation

### Security
- Basic kill switch implementation
- Network namespace isolation

## [0.2.0] - 2025-12-15

### Added
- Network namespace creation and management
- veth pair setup for host-namespace communication
- WireGuard configuration generation
- Basic configuration file support

## [0.1.0] - 2025-12-01

### Added
- Initial project structure
- Basic VPN connection management concept
- README with project goals
