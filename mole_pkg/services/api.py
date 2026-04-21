"""
MOLE HTTP Control API Service - REST API for querying and controlling MOLE
"""

import asyncio
import hmac
import json
from typing import TYPE_CHECKING

from ..utils import log, run_in_netns

if TYPE_CHECKING:
    from ..mole import Mole


class HTTPAPIServer:
    """Simple HTTP API server for querying/controlling mole"""

    def __init__(self, mole: "Mole", bind: str, port: int, api_key: str = ''):
        self.mole = mole
        self.bind = bind
        self.port = port
        self.api_key = api_key
        self._server = None

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
            # No API key configured - allow all (localhost only recommended)
            return True

        # Use constant-time comparison to prevent timing attacks
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
                await self._send_response(writer, 401, {"error": "Unauthorized", "message": "Invalid or missing API key"})
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
            await writer.wait_closed()

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

    async def _get_status(self) -> dict:
        """GET /v1/status - VPN connection status"""
        state = self.mole.state
        return {
            'status': 200,
            'body': {
                'connected': state.connected,
                'server': state.server_hostname,
                'server_ip': state.server_ip,
                'peer_ip': state.peer_ip,
                'port': state.port,
                'port_forward_enabled': self.mole.config.port_forward,
            }
        }

    async def _get_port(self) -> dict:
        """GET /v1/port - Current forwarded port"""
        port = self.mole.state.port
        return {
            'status': 200,
            'body': {
                'port': port,
                'enabled': self.mole.config.port_forward,
            }
        }

    async def _get_ip(self) -> dict:
        """GET /v1/ip - Public IP address"""
        try:
            result = run_in_netns(
                ["curl", "-s", "--max-time", "5", "https://ifconfig.me"],
                self.mole.config.netns, check=False
            )
            ip = result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            ip = None

        return {
            'status': 200,
            'body': {
                'public_ip': ip,
                'server_ip': self.mole.state.server_ip,
            }
        }

    async def _get_server(self) -> dict:
        """GET /v1/server - Current server info"""
        state = self.mole.state
        return {
            'status': 200,
            'body': {
                'hostname': state.server_hostname,
                'ip': state.server_ip,
                'vip': state.server_vip,
            }
        }

    async def _get_health(self) -> dict:
        """GET /v1/health - Health check status"""
        # Check WireGuard interface
        result = run_in_netns(["wg", "show", "mole"], self.mole.config.netns, check=False)
        wg_up = result.returncode == 0

        # Check connectivity
        ping_result = run_in_netns(
            ["ping", "-c", "1", "-W", "2", "1.1.1.1"],
            self.mole.config.netns, check=False
        )
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
        """GET /v1/dns - DNS over TLS status, cache stats, and query counters"""
        config = self.mole.config
        dns_server = getattr(self.mole, '_dns_server', None)

        cache_size = 0
        cache_entries = 0
        blocked_domains = 0
        in_flight = 0
        last_blocklist_update = None
        counters: dict = {}
        upstreams: list = []

        if dns_server:
            cache_entries = len(dns_server._cache)
            cache_size = sum(len(v[0]) for v in dns_server._cache.values())
            blocked_domains = len(dns_server.blocked_domains)
            in_flight = len(getattr(dns_server, '_in_flight', {}))
            if dns_server._last_blocklist_update > 0:
                last_blocklist_update = int(dns_server._last_blocklist_update)
            counters = dict(getattr(dns_server, '_stats', {}) or {})
            pool = getattr(dns_server, '_pool', None)
            if pool is not None:
                upstreams = pool.upstream_info()

        return {
            'status': 200,
            'body': {
                'enabled': config.dot_enabled,
                'upstream': config.dot_upstream,
                'upstreams': upstreams,
                'caching': config.dot_caching,
                'cache_entries': cache_entries,
                'cache_size_bytes': cache_size,
                'blocked_domains': blocked_domains,
                'in_flight': in_flight,
                'counters': counters,
                'last_blocklist_update': last_blocklist_update,
                'block_ads': config.dot_block_ads,
                'block_malware': config.dot_block_malware,
                'block_tracking': config.dot_block_tracking,
            }
        }

    async def _put_restart(self) -> dict:
        """PUT /v1/vpn/restart - Trigger VPN reconnection"""
        log.info("API: Restart requested")
        # Schedule renewal in background
        asyncio.create_task(self.mole._full_renewal())
        return {
            'status': 200,
            'body': {
                'message': 'Restart initiated',
            }
        }
