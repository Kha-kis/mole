#!/usr/bin/env python3
"""
MOLE HTTP Proxy Server - Standalone entry point for running in namespace

When run inside the VPN namespace, connections naturally go through the VPN
without needing 'ip netns exec' wrappers.

Usage:
    ip netns exec vpn python3 -m mole_pkg.services.proxy_main [options]
"""

import argparse
import asyncio
import base64
import hmac
import os
import signal
import sys
from pathlib import Path

# Add parent to path for imports when run standalone
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mole_pkg.utils import log


# Private/internal IP ranges to block (SSRF protection)
BLOCKED_NETWORKS = [
    ('127.',),               # Loopback
    ('10.',),                # Private Class A
    ('192.168.',),           # Private Class C
    ('172.16.', '172.17.', '172.18.', '172.19.',   # Private Class B
     '172.20.', '172.21.', '172.22.', '172.23.',
     '172.24.', '172.25.', '172.26.', '172.27.',
     '172.28.', '172.29.', '172.30.', '172.31.'),
    ('169.254.',),           # Link-local / Cloud metadata
    ('0.',),                 # Invalid
    ('255.',),               # Broadcast
]


class HTTPProxyServerStandalone:
    """Authenticated HTTP proxy that runs inside VPN namespace"""

    def __init__(self, bind: str, port: int, user: str, password: str,
                 veth_host_ip: str = "10.200.200.1", veth_vpn_ip: str = "10.200.200.2"):
        self.bind = bind
        self.port = port
        self.user = user
        self.password = password
        self.veth_host_ip = veth_host_ip
        self.veth_vpn_ip = veth_vpn_ip
        self._server = None

    def _is_blocked_target(self, host: str) -> bool:
        """Check if target host is internal/private (SSRF protection)"""
        # Block localhost by name
        if host.lower() in ('localhost', 'localhost.localdomain'):
            return True

        # Block cloud metadata hostnames
        if host.lower() in ('metadata.google.internal', 'metadata', '169.254.169.254'):
            return True

        # Block internal veth addresses
        if host == self.veth_host_ip or host == self.veth_vpn_ip:
            return True

        # Check if it looks like an IP address
        parts = host.split('.')
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            # It's an IPv4 address - check against blocked networks
            for network_group in BLOCKED_NETWORKS:
                for prefix in network_group:
                    if host.startswith(prefix):
                        return True

        return False

    async def start(self):
        """Start the HTTP proxy server"""
        self._server = await asyncio.start_server(
            self._handle_connection, self.bind, self.port
        )
        log.info(f"HTTP Proxy server listening on {self.bind}:{self.port}")
        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        """Stop the HTTP proxy server"""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming proxy connection"""
        try:
            # Read request line
            request_line = await asyncio.wait_for(reader.readline(), timeout=30.0)
            if not request_line:
                return

            request_line = request_line.decode('utf-8', errors='ignore').strip()
            parts = request_line.split(' ')
            if len(parts) < 3:
                await self._send_error(writer, 400, "Bad Request")
                return

            method, target, _ = parts[0], parts[1], parts[2]

            # Read headers
            headers = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=30.0)
                if line == b'\r\n' or line == b'\n' or not line:
                    break
                if b':' in line:
                    key, value = line.decode('utf-8', errors='ignore').split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            # Check authentication
            if not self._check_auth(headers):
                await self._send_auth_required(writer)
                return

            # Handle CONNECT method (HTTPS tunneling)
            if method == 'CONNECT':
                await self._handle_connect(target, reader, writer)
            else:
                # Handle regular HTTP request
                await self._handle_http(method, target, headers, reader, writer)

        except asyncio.TimeoutError:
            log.debug("Proxy connection timeout")
        except Exception as e:
            log.error(f"Proxy error: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _check_auth(self, headers: dict) -> bool:
        """Verify proxy authentication using constant-time comparison"""
        auth = headers.get('proxy-authorization', '')
        if not auth.startswith('Basic '):
            return False
        try:
            credentials = base64.b64decode(auth[6:]).decode('utf-8')
            user, passwd = credentials.split(':', 1)
            # Use constant-time comparison to prevent timing attacks
            user_match = hmac.compare_digest(user.encode('utf-8'), self.user.encode('utf-8'))
            pass_match = hmac.compare_digest(passwd.encode('utf-8'), self.password.encode('utf-8'))
            return user_match and pass_match
        except (ValueError, UnicodeDecodeError, base64.binascii.Error):
            return False

    async def _send_auth_required(self, writer: asyncio.StreamWriter):
        """Send 407 Proxy Authentication Required"""
        response = "HTTP/1.1 407 Proxy Authentication Required\r\n"
        response += 'Proxy-Authenticate: Basic realm="mole"\r\n'
        response += "Content-Length: 0\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        writer.write(response.encode('utf-8'))
        await writer.drain()

    async def _send_error(self, writer: asyncio.StreamWriter, code: int, message: str):
        """Send HTTP error response"""
        response = f"HTTP/1.1 {code} {message}\r\n"
        response += "Content-Length: 0\r\n"
        response += "Connection: close\r\n"
        response += "\r\n"
        writer.write(response.encode('utf-8'))
        await writer.drain()

    async def _handle_connect(self, target: str, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter):
        """Handle CONNECT method for HTTPS tunneling"""
        # Parse target (host:port)
        if ':' in target:
            host, port_str = target.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                await self._send_error(writer, 400, "Invalid port")
                return
        else:
            host, port = target, 443

        # SSRF protection: block internal/private addresses
        if self._is_blocked_target(host):
            log.warning(f"Proxy SSRF blocked: {host}:{port}")
            await self._send_error(writer, 403, "Forbidden")
            return

        try:
            # Connect directly to target (we're already in the namespace)
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=30.0
            )

            # Send connection established
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            # Bidirectional tunnel
            await asyncio.gather(
                self._pipe(reader, upstream_writer),
                self._pipe(upstream_reader, writer),
                return_exceptions=True
            )

        except asyncio.TimeoutError:
            log.warning(f"Connection timeout: {host}:{port}")
            await self._send_error(writer, 504, "Gateway Timeout")
        except OSError as e:
            log.warning(f"Connection failed to {host}:{port}: {e}")
            await self._send_error(writer, 502, "Bad Gateway")
        except Exception as e:
            log.error(f"CONNECT tunnel error: {e}")
            await self._send_error(writer, 502, "Bad Gateway")

    async def _handle_http(self, method: str, target: str, headers: dict,
                           reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle regular HTTP request through proxy"""
        try:
            # Parse URL
            if target.startswith('http://'):
                url = target[7:]
            else:
                url = target

            if '/' in url:
                host_port, path = url.split('/', 1)
                path = '/' + path
            else:
                host_port = url
                path = '/'

            if ':' in host_port:
                host, port_str = host_port.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    await self._send_error(writer, 400, "Invalid port")
                    return
            else:
                host, port = host_port, 80

            # SSRF protection: block internal/private addresses
            if self._is_blocked_target(host):
                log.warning(f"Proxy SSRF blocked: {host}:{port}")
                await self._send_error(writer, 403, "Forbidden")
                return

            # Connect directly to target (we're already in the namespace)
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=30.0
            )

            # Build request to forward
            request = f"{method} {path} HTTP/1.1\r\n"
            request += f"Host: {host}\r\n"
            for key, value in headers.items():
                if key not in ('proxy-authorization', 'proxy-connection'):
                    request += f"{key}: {value}\r\n"
            request += "Connection: close\r\n"
            request += "\r\n"

            # Read body if present
            content_length = int(headers.get('content-length', 0))
            body = b''
            if content_length > 0:
                body = await reader.read(content_length)

            # Send request
            upstream_writer.write(request.encode('utf-8'))
            upstream_writer.write(body)
            await upstream_writer.drain()

            # Read and forward response
            response = await upstream_reader.read()
            writer.write(response)
            await writer.drain()

            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except Exception:
                pass

        except asyncio.TimeoutError:
            log.warning(f"Connection timeout")
            await self._send_error(writer, 504, "Gateway Timeout")
        except OSError as e:
            log.warning(f"Connection failed: {e}")
            await self._send_error(writer, 502, "Bad Gateway")
        except Exception as e:
            log.error(f"HTTP proxy error: {e}")
            await self._send_error(writer, 502, "Bad Gateway")

    async def _pipe(self, reader, writer):
        """Pipe data from reader to writer"""
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                if hasattr(writer, 'close'):
                    writer.close()
            except Exception:
                pass


async def main_async(args):
    """Async main entry point"""
    server = HTTPProxyServerStandalone(
        bind=args.bind,
        port=args.port,
        user=args.user,
        password=args.password,
        veth_host_ip=args.veth_host_ip,
        veth_vpn_ip=args.veth_vpn_ip,
    )

    # Setup signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()

    def signal_handler():
        log.info("Proxy server received shutdown signal")
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

    log.info("Proxy server stopped")


def main():
    parser = argparse.ArgumentParser(
        description="MOLE HTTP Proxy Server (runs inside VPN namespace)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --bind 0.0.0.0 --port 8888 --user mole --password secret

When run inside the VPN namespace, all proxy connections automatically
go through the VPN tunnel.
"""
    )

    parser.add_argument("--bind", default="0.0.0.0",
                        help="Address to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8888,
                        help="Port to listen on (default: 8888)")
    parser.add_argument("--user", required=True,
                        help="Proxy authentication username")
    parser.add_argument("--password", default=None,
                        help="Proxy authentication password (or use MOLE_PROXY_PASS env var)")
    parser.add_argument("--veth-host-ip", default="10.200.200.1",
                        help="Host veth IP (for SSRF blocking)")
    parser.add_argument("--veth-vpn-ip", default="10.200.200.2",
                        help="VPN veth IP (for SSRF blocking)")

    args = parser.parse_args()

    # Get password from argument or environment variable
    password = args.password or os.environ.get('MOLE_PROXY_PASS', '')
    if not password:
        log.error("Password required: use --password or set MOLE_PROXY_PASS environment variable")
        return 1
    args.password = password

    log.info(f"Starting HTTP Proxy on {args.bind}:{args.port}")

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
