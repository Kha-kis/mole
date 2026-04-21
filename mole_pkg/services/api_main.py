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
            await self._send_response(writer, response['status'], response['body'])

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
            ('PUT', '/v1/vpn/restart'): self._put_restart,
            ('POST', '/v1/vpn/restart'): self._put_restart,
        }

        handler = routes.get((method, path))
        if handler:
            return await handler()

        return {'status': 404, 'body': {"error": "Not found", "path": path}}

    async def _send_response(self, writer: asyncio.StreamWriter, status: int, body: dict):
        """Send HTTP response"""
        status_messages = {
            200: 'OK', 400: 'Bad Request', 401: 'Unauthorized', 404: 'Not Found',
            408: 'Request Timeout', 500: 'Internal Server Error'
        }
        body_bytes = json.dumps(body, indent=2).encode('utf-8')

        response = f"HTTP/1.1 {status} {status_messages.get(status, 'Unknown')}\r\n"
        response += "Content-Type: application/json\r\n"
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
