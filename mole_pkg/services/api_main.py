#!/usr/bin/env python3
"""
MOLE HTTP Control API Server - Standalone entry point for running in namespace

When run inside the VPN namespace, can directly query WireGuard status.
Communicates with main orchestrator via files.

Usage:
    ip netns exec vpn python3 -m mole_pkg.services.api_main [options]
"""

import argparse
import asyncio
import hmac
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# Add parent to path for imports when run standalone
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mole_pkg.utils import log
from mole_pkg import __version__


# Prometheus exposition format helpers — module-level so the formatter is a
# pure function the tests can call without spinning up a server.

_PROM_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _prom_escape_label(value: str) -> str:
    """Escape a Prometheus label value per the exposition format spec.

    Order matters: backslash first so the others' escapes aren't re-escaped.
    """
    if value is None:
        return ""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


def _prom_num(value, default: float = 0.0) -> float:
    """Coerce a metric value to a float for emission, defaulting on junk.

    Prometheus accepts int and float; we always emit float-friendly numbers
    via repr so 0 stays "0" and floats stay un-rounded.
    """
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def format_prometheus_metrics(
    dns_stats: dict,
    vpn_status: dict,
    version: str = "",
) -> str:
    """Render mole's runtime state as Prometheus text exposition format.

    Inputs are dict-shaped to keep the function pure and trivially testable
    without a running server. Empty/missing fields render gracefully:
    counters default to 0, per-upstream rows are skipped when no upstreams
    are configured, and any field that fails coercion falls back to 0
    rather than raising.
    """
    dns_stats = dns_stats or {}
    vpn_status = vpn_status or {}
    counters = dns_stats.get("counters") or {}
    upstreams = dns_stats.get("upstreams") or []

    out: list = []

    def emit(name: str, mtype: str, help_text: str, samples):
        """Append one metric block (HELP, TYPE, sample lines, blank)."""
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {mtype}")
        for labels, value in samples:
            if labels:
                label_str = ",".join(
                    f'{k}="{_prom_escape_label(v)}"' for k, v in labels.items()
                )
                out.append(f"{name}{{{label_str}}} {value}")
            else:
                out.append(f"{name} {value}")
        out.append("")

    # ---- Build info ----
    if version:
        emit(
            "mole_build_info",
            "gauge",
            "Build metadata for the running mole instance.",
            [({"version": version}, 1)],
        )

    # ---- VPN ----
    emit(
        "mole_vpn_connected",
        "gauge",
        "1 if the WireGuard tunnel is currently up, 0 otherwise.",
        [(None, 1 if vpn_status.get("connected") else 0)],
    )

    port = vpn_status.get("port") or 0
    emit(
        "mole_vpn_forwarded_port",
        "gauge",
        "Currently forwarded VPN port (0 if no port forward).",
        [(None, int(_prom_num(port)))],
    )

    # ---- DNS aggregates ----
    counter_specs = [
        ("mole_dns_queries_total", "queries_total",
         "Total DNS queries received by the resolver."),
        ("mole_dns_cache_hits_total", "cache_hits",
         "DNS responses served from cache."),
        ("mole_dns_cache_misses_total", "cache_misses",
         "DNS queries that missed cache and went to an upstream."),
        ("mole_dns_blocked_total", "blocked",
         "DNS queries answered as blocked (NXDOMAIN/0.0.0.0)."),
        ("mole_dns_resolve_errors_total", "resolve_errors",
         "DNS queries that failed before any upstream attempt."),
        ("mole_dns_singleflight_collapses_total", "singleflight_collapses",
         "Concurrent identical queries collapsed onto one upstream call."),
    ]
    for metric_name, key, help_text in counter_specs:
        emit(
            metric_name,
            "counter",
            help_text,
            [(None, int(_prom_num(counters.get(key, 0))))],
        )

    gauge_specs = [
        ("mole_dns_in_flight_peak", "in_flight_peak", counters,
         "Peak number of in-flight upstream queries observed."),
        ("mole_dns_cache_entries", "cache_entries", dns_stats,
         "Current number of cached DNS responses."),
        ("mole_dns_cache_size_bytes", "cache_size_bytes", dns_stats,
         "Approximate total bytes held in the DNS cache."),
        ("mole_dns_blocked_domains", "blocked_domains", dns_stats,
         "Number of domains in the active blocklist."),
    ]
    for metric_name, key, source, help_text in gauge_specs:
        emit(
            metric_name,
            "gauge",
            help_text,
            [(None, int(_prom_num(source.get(key, 0))))],
        )

    last_update = dns_stats.get("last_blocklist_update") or 0
    emit(
        "mole_dns_blocklist_last_update_seconds",
        "gauge",
        "Unix timestamp of the most recent blocklist refresh (0 if never).",
        [(None, int(_prom_num(last_update)))],
    )

    # ---- Per-upstream ----
    if upstreams:
        # Each metric is emitted with all upstreams as separate samples to
        # keep HELP/TYPE blocks together (Prometheus rejects duplicate
        # HELP/TYPE for the same metric name).
        upstream_counter_specs = [
            ("mole_dns_upstream_queries_total", "queries",
             "Per-upstream successful query counter."),
            ("mole_dns_upstream_errors_total", "errors",
             "Per-upstream upstream errors (timeouts, connection failures)."),
            ("mole_dns_upstream_retries_total", "retries",
             "Per-upstream retry attempts within the upstream's own retry budget."),
            ("mole_dns_upstream_failovers_total", "failovers_out",
             "Times this upstream's retry budget was exhausted and the next upstream was tried."),
        ]
        for metric_name, key, help_text in upstream_counter_specs:
            samples = []
            for u in upstreams:
                name = u.get("name") or "unknown"
                cnt = (u.get("counters") or {}).get(key, 0)
                samples.append(({"upstream": name}, int(_prom_num(cnt))))
            emit(metric_name, "counter", help_text, samples)

        # Open connections + pool size as gauges.
        for metric_name, key, help_text in [
            ("mole_dns_upstream_open_connections", "open_connections",
             "Currently open TLS connections in the upstream's pool."),
            ("mole_dns_upstream_pool_size", "pool_size",
             "Configured pool size for the upstream."),
        ]:
            samples = []
            for u in upstreams:
                name = u.get("name") or "unknown"
                samples.append(
                    ({"upstream": name}, int(_prom_num(u.get(key, 0))))
                )
            emit(metric_name, "gauge", help_text, samples)

        # Latency percentiles as separate gauges (one metric per quantile).
        # Convert ms -> seconds to match Prometheus latency conventions.
        # Skip upstreams with no samples yet (rendering "None" would be invalid).
        for metric_name, key, help_text in [
            ("mole_dns_upstream_query_latency_p50_seconds", "query_p50_ms",
             "Per-upstream DoT query latency P50 over the rolling window (seconds)."),
            ("mole_dns_upstream_query_latency_p95_seconds", "query_p95_ms",
             "Per-upstream DoT query latency P95 over the rolling window (seconds)."),
            ("mole_dns_upstream_query_latency_p99_seconds", "query_p99_ms",
             "Per-upstream DoT query latency P99 over the rolling window (seconds)."),
        ]:
            samples = []
            for u in upstreams:
                ms = u.get(key)
                if ms is None:
                    continue
                name = u.get("name") or "unknown"
                # Round to 6 decimals to avoid IEEE 754 noise on the
                # ms→s division (e.g. 54.8/1000 = 0.054799999999999995).
                samples.append(
                    ({"upstream": name}, round(_prom_num(ms) / 1000.0, 6))
                )
            if samples:
                emit(metric_name, "gauge", help_text, samples)

        # Latency sample count as a gauge — Prometheus convention would
        # use _count for summaries, but we don't expose a sum so a plain
        # gauge avoids the ambiguity.
        samples = []
        for u in upstreams:
            name = u.get("name") or "unknown"
            samples.append(
                ({"upstream": name}, int(_prom_num(u.get("query_samples", 0))))
            )
        emit(
            "mole_dns_upstream_query_latency_samples",
            "gauge",
            "Number of latency samples currently held in the upstream's rolling window.",
            samples,
        )

    return "\n".join(out) + "\n"


class HTTPAPIServerStandalone:
    """HTTP API server that runs inside VPN namespace"""

    def __init__(self, bind: str, port: int, api_key: str, state_dir: str,
                 config_file: str = None):
        self.bind = bind
        self.port = port
        self.api_key = api_key
        self.state_dir = Path(state_dir)
        self.config_file = config_file
        self._server = None
        self._config_cache = {}
        self._config_mtime = 0

    def _read_state_file(self, name: str) -> str:
        """Read a state file"""
        path = self.state_dir / name
        try:
            if path.exists():
                return path.read_text().strip()
        except Exception:
            pass
        return None

    def _read_config(self) -> dict:
        """Read and cache config file"""
        if not self.config_file:
            return {}

        try:
            mtime = os.path.getmtime(self.config_file)
            if mtime > self._config_mtime:
                self._config_cache = {}
                self._config_mtime = mtime
                with open(self.config_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            self._config_cache[key.strip()] = value.strip()
        except Exception:
            pass
        return self._config_cache

    def _get_config(self, key: str, default: str = '') -> str:
        """Get config value"""
        config = self._read_config()
        return config.get(key, default)

    def _get_config_bool(self, key: str, default: bool = False) -> bool:
        """Get boolean config value"""
        val = self._get_config(key, str(default)).lower()
        return val in ('true', '1', 'yes', 'on')

    async def start(self):
        """Start the HTTP API server"""
        self._server = await asyncio.start_server(
            self._handle_request, self.bind, self.port
        )
        auth_status = "enabled" if self.api_key else "DISABLED (no API key set)"
        log.info(f"HTTP API server listening on {self.bind}:{self.port}")
        log.info(f"HTTP API authentication: {auth_status}")
        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        """Stop the HTTP API server"""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    def _check_auth(self, headers: dict, query_params: dict) -> bool:
        """Check API key authentication using constant-time comparison"""
        if not self.api_key:
            return True

        api_key_bytes = self.api_key.encode('utf-8')

        # Check X-API-Key header
        header_key = headers.get('x-api-key', '')
        if header_key and hmac.compare_digest(header_key.encode('utf-8'), api_key_bytes):
            return True

        # Check Authorization: Bearer <key>
        auth_header = headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            bearer_key = auth_header[7:]
            if bearer_key and hmac.compare_digest(bearer_key.encode('utf-8'), api_key_bytes):
                return True

        # Check ?api_key= query parameter
        query_key = query_params.get('api_key', '')
        if query_key and hmac.compare_digest(query_key.encode('utf-8'), api_key_bytes):
            return True

        return False

    def _parse_query_params(self, path: str) -> tuple:
        """Parse path and query parameters"""
        if '?' in path:
            path_part, query_string = path.split('?', 1)
            params = {}
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value
            return path_part, params
        return path, {}

    async def _handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming HTTP request"""
        try:
            # Read request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            if not request_line:
                return

            request_line = request_line.decode('utf-8').strip()
            parts = request_line.split(' ')
            if len(parts) < 2:
                await self._send_response(writer, 400, {"error": "Bad request"})
                return

            method, full_path = parts[0], parts[1]
            path, query_params = self._parse_query_params(full_path)

            # Read headers
            headers = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5.0)
                if line == b'\r\n' or line == b'\n' or not line:
                    break
                if b':' in line:
                    key, value = line.decode('utf-8').split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            # Check authentication
            if not self._check_auth(headers, query_params):
                await self._send_response(writer, 401, {"error": "Unauthorized"})
                return

            # Route request
            response = await self._route_request(method, path)
            await self._send_response(
                writer,
                response['status'],
                response['body'],
                content_type=response.get('content_type'),
            )

        except asyncio.TimeoutError:
            await self._send_response(writer, 408, {"error": "Request timeout"})
        except Exception as e:
            log.error(f"API request error: {e}")
            await self._send_response(writer, 500, {"error": "Internal server error"})
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _route_request(self, method: str, path: str) -> dict:
        """Route request to appropriate handler"""
        routes = {
            ('GET', '/v1/status'): self._get_status,
            ('GET', '/v1/port'): self._get_port,
            ('GET', '/v1/ip'): self._get_ip,
            ('GET', '/v1/server'): self._get_server,
            ('GET', '/v1/health'): self._get_health,
            ('GET', '/v1/dns'): self._get_dns,
            ('GET', '/metrics'): self._get_metrics,
            ('PUT', '/v1/vpn/restart'): self._put_restart,
            ('POST', '/v1/vpn/restart'): self._put_restart,
        }

        handler = routes.get((method, path))
        if handler:
            return await handler()

        return {'status': 404, 'body': {"error": "Not found", "path": path}}

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        status: int,
        body,
        content_type: str = None,
    ):
        """Send HTTP response.

        body may be a dict (JSON-encoded) or a str (sent as-is). When
        content_type is omitted the function picks JSON for dict and
        text/plain for str so handlers don't have to specify it.
        """
        status_messages = {
            200: 'OK', 400: 'Bad Request', 401: 'Unauthorized', 404: 'Not Found',
            408: 'Request Timeout', 500: 'Internal Server Error'
        }

        if isinstance(body, str):
            body_bytes = body.encode('utf-8')
            ct = content_type or 'text/plain; charset=utf-8'
        else:
            body_bytes = json.dumps(body, indent=2).encode('utf-8')
            ct = content_type or 'application/json'

        response = f"HTTP/1.1 {status} {status_messages.get(status, 'Unknown')}\r\n"
        response += f"Content-Type: {ct}\r\n"
        response += f"Content-Length: {len(body_bytes)}\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"

        writer.write(response.encode('utf-8'))
        writer.write(body_bytes)
        await writer.drain()

    def _run_cmd(self, cmd: list) -> subprocess.CompletedProcess:
        """Run a command (we're already in the namespace)"""
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except Exception as e:
            return subprocess.CompletedProcess(cmd, 1, '', str(e))

    async def _get_status(self) -> dict:
        """GET /v1/status - VPN connection status"""
        # Read state from files
        server_hostname = self._read_state_file('hostname')
        server_ip = self._read_state_file('server_ip')
        port = self._read_state_file('port')
        peer_ip = self._read_state_file('peer_ip')

        # Check if WireGuard is up
        result = self._run_cmd(['wg', 'show', 'mole'])
        connected = result.returncode == 0

        return {
            'status': 200,
            'body': {
                'connected': connected,
                'server': server_hostname,
                'server_ip': server_ip,
                'peer_ip': peer_ip,
                'port': int(port) if port and port.isdigit() else None,
                'port_forward_enabled': self._get_config_bool('PORT_FORWARD', True),
            }
        }

    async def _get_port(self) -> dict:
        """GET /v1/port - Current forwarded port"""
        port = self._read_state_file('port')
        return {
            'status': 200,
            'body': {
                'port': int(port) if port and port.isdigit() else None,
                'enabled': self._get_config_bool('PORT_FORWARD', True),
            }
        }

    async def _get_ip(self) -> dict:
        """GET /v1/ip - Public IP address"""
        # We're in the namespace, so curl goes through VPN directly
        result = self._run_cmd(['curl', '-s', '--max-time', '5', 'https://ifconfig.me'])
        ip = result.stdout.strip() if result.returncode == 0 else None

        server_ip = self._read_state_file('server_ip')

        return {
            'status': 200,
            'body': {
                'public_ip': ip,
                'server_ip': server_ip,
            }
        }

    async def _get_server(self) -> dict:
        """GET /v1/server - Current server info"""
        return {
            'status': 200,
            'body': {
                'hostname': self._read_state_file('hostname'),
                'ip': self._read_state_file('server_ip'),
                'vip': self._read_state_file('server_vip'),
            }
        }

    async def _get_health(self) -> dict:
        """GET /v1/health - Health check status"""
        # Check WireGuard interface (we're in namespace, run directly)
        result = self._run_cmd(['wg', 'show', 'mole'])
        wg_up = result.returncode == 0

        # Check connectivity
        ping_result = self._run_cmd(['ping', '-c', '1', '-W', '2', '1.1.1.1'])
        connected = ping_result.returncode == 0

        return {
            'status': 200,
            'body': {
                'healthy': wg_up and connected,
                'wireguard_up': wg_up,
                'internet_connected': connected,
            }
        }

    async def _get_dns(self) -> dict:
        """GET /v1/dns - DNS over TLS status, cache stats, and query counters.

        Stats are produced by dns_main as JSON in dns_stats.json (the dns_main
        process is the only one with live access to DOTServer state).
        """
        dns_stats_file = self.state_dir / 'dns_stats.json'
        dns_stats: dict = {}
        try:
            if dns_stats_file.exists():
                dns_stats = json.loads(dns_stats_file.read_text())
        except Exception:
            pass

        last_update = dns_stats.get('last_blocklist_update') or 0
        last_update_int = int(last_update) if last_update else None

        return {
            'status': 200,
            'body': {
                'enabled': self._get_config_bool('DOT_ENABLED', False),
                'upstream': self._get_config('DOT_UPSTREAM', 'cloudflare'),
                'upstreams': dns_stats.get('upstreams', []),
                'caching': self._get_config_bool('DOT_CACHING', True),
                'cache_entries': dns_stats.get('cache_entries', 0),
                'cache_size_bytes': dns_stats.get('cache_size_bytes', 0),
                'blocked_domains': dns_stats.get('blocked_domains', 0),
                'in_flight': dns_stats.get('in_flight', 0),
                'counters': dns_stats.get('counters', {}),
                'last_blocklist_update': last_update_int,
                'block_ads': self._get_config_bool('DOT_BLOCK_ADS', True),
                'block_malware': self._get_config_bool('DOT_BLOCK_MALWARE', True),
                'block_tracking': self._get_config_bool('DOT_BLOCK_TRACKING', False),
            }
        }

    async def _get_metrics(self) -> dict:
        """GET /metrics - Prometheus exposition format.

        Same data as /v1/dns and /v1/status, re-shaped for time-series
        scraping. Reuses dns_stats.json (written by dns_main) plus state
        files for VPN connectivity, so this is a thin formatter, not a
        new collector. Goes through the same _check_auth path as the
        rest of the API; Prometheus scrapers should set
        `authorization: { credentials: <HTTP_API_KEY> }` in scrape_config.
        """
        # DNS state (same source as _get_dns)
        dns_stats_file = self.state_dir / 'dns_stats.json'
        dns_stats: dict = {}
        try:
            if dns_stats_file.exists():
                dns_stats = json.loads(dns_stats_file.read_text())
        except Exception:
            pass

        # VPN status (same shape as _get_status without re-running wg show
        # if we already determined connectivity). Read state files and
        # check WireGuard.
        port_str = self._read_state_file('port')
        port = int(port_str) if port_str and port_str.isdigit() else 0
        wg_result = self._run_cmd(['wg', 'show', 'mole'])
        vpn_status = {
            'connected': wg_result.returncode == 0,
            'port': port,
        }

        body = format_prometheus_metrics(
            dns_stats=dns_stats,
            vpn_status=vpn_status,
            version=__version__,
        )

        return {
            'status': 200,
            'body': body,
            'content_type': _PROM_CONTENT_TYPE,
        }

    async def _put_restart(self) -> dict:
        """PUT /v1/vpn/restart - Trigger VPN reconnection"""
        log.info("API: Restart requested")

        # Signal restart by writing to trigger file
        trigger_file = self.state_dir / 'restart_trigger'
        try:
            trigger_file.write_text(str(time.time()))
            log.info(f"Restart trigger written to {trigger_file}")
        except Exception as e:
            log.error(f"Failed to write restart trigger: {e}")
            return {
                'status': 500,
                'body': {'error': 'Failed to trigger restart'}
            }

        return {
            'status': 200,
            'body': {
                'message': 'Restart initiated',
            }
        }


async def main_async(args):
    """Async main entry point"""
    server = HTTPAPIServerStandalone(
        bind=args.bind,
        port=args.port,
        api_key=args.api_key or '',
        state_dir=args.state_dir,
        config_file=args.config,
    )

    # Setup signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()

    def signal_handler():
        log.info("API server received shutdown signal")
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    # Start server in background
    server_task = asyncio.create_task(server.start())

    # Wait for shutdown signal
    await shutdown_event.wait()

    # Cleanup
    await server.stop()
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass

    log.info("API server stopped")


def main():
    parser = argparse.ArgumentParser(
        description="MOLE HTTP API Server (runs inside VPN namespace)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Endpoints:
  GET  /v1/status      - VPN connection status
  GET  /v1/port        - Current forwarded port
  GET  /v1/ip          - Public IP address
  GET  /v1/server      - Server info
  GET  /v1/health      - Health check
  GET  /v1/dns         - DNS server stats
  PUT  /v1/vpn/restart - Trigger VPN restart

Examples:
  %(prog)s --bind 0.0.0.0 --port 8080
  %(prog)s --bind 0.0.0.0 --port 8080 --api-key mysecretkey
"""
    )

    parser.add_argument("--bind", default="0.0.0.0",
                        help="Address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port to listen on (default: 8080)")
    parser.add_argument("--api-key", default="",
                        help="API key for authentication (optional)")
    parser.add_argument("--state-dir", default="/var/lib/mole",
                        help="State directory for reading VPN state")
    parser.add_argument("--config", default="/etc/mole/config",
                        help="Config file path")

    args = parser.parse_args()

    if not args.api_key:
        log.warning("No API key set - API is accessible without authentication!")

    log.info(f"Starting HTTP API on {args.bind}:{args.port}")

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
