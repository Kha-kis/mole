"""
MOLE HTTP Proxy Service - Authenticated proxy through VPN namespace
"""

import asyncio
import base64
import hmac
from typing import TYPE_CHECKING

from ..utils import log

if TYPE_CHECKING:
    from ..config import Config


class HTTPProxyServer:
    """Authenticated HTTP proxy that routes traffic through VPN namespace"""

    # Private/internal IP ranges to block (SSRF protection)
    BLOCKED_NETWORKS = [
        ('127.', ),              # Loopback
        ('10.', ),               # Private Class A
        ('192.168.', ),          # Private Class C
        ('172.16.', '172.17.', '172.18.', '172.19.',  # Private Class B
         '172.20.', '172.21.', '172.22.', '172.23.',
         '172.24.', '172.25.', '172.26.', '172.27.',
         '172.28.', '172.29.', '172.30.', '172.31.'),
        ('169.254.', ),          # Link-local / Cloud metadata
        ('0.', ),                # Invalid
        ('255.', ),              # Broadcast
    ]

    def __init__(self, config: "Config", netns: str):
        self.config = config
        self.netns = netns
        self.bind = config.proxy_bind
        self.port = config.proxy_port
        self.user = config.proxy_user
        self.password = config.proxy_pass
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
        if host == self.config.veth_host_ip or host == self.config.veth_vpn_ip:
            return True

        # Check if it looks like an IP address
        parts = host.split('.')
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            # It's an IPv4 address - check against blocked networks
            for network_group in self.BLOCKED_NETWORKS:
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
            # Connect to target through namespace using socat
            # Using create_subprocess_exec (safe, no shell injection)
            proc = await asyncio.create_subprocess_exec(
                'ip', 'netns', 'exec', self.netns,
                'socat', '-', f'TCP:{host}:{port}',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )

            # Send connection established
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            # Bidirectional tunnel
            await asyncio.gather(
                self._pipe(reader, proc.stdin),
                self._pipe_proc(proc.stdout, writer),
                return_exceptions=True
            )

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

            # Forward request through namespace (safe, no shell)
            proc = await asyncio.create_subprocess_exec(
                'ip', 'netns', 'exec', self.netns,
                'socat', '-', f'TCP:{host}:{port}',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )

            # Send request
            proc.stdin.write(request.encode('utf-8'))
            proc.stdin.write(body)
            await proc.stdin.drain()
            proc.stdin.close()

            # Read and forward response
            response = await proc.stdout.read()
            writer.write(response)
            await writer.drain()

        except Exception as e:
            log.error(f"HTTP proxy error: {e}")
            await self._send_error(writer, 502, "Bad Gateway")

    async def _pipe(self, reader: asyncio.StreamReader, writer):
        """Pipe data from reader to subprocess stdin"""
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
                writer.close()
            except Exception:
                pass

    async def _pipe_proc(self, proc_stdout, writer: asyncio.StreamWriter):
        """Pipe data from subprocess stdout to writer"""
        try:
            while True:
                data = await proc_stdout.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
