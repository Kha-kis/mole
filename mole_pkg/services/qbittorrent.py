"""
MOLE qBittorrent Service - Torrent client integration
"""

import asyncio
import base64
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

from ..utils import log

if TYPE_CHECKING:
    from ..config import Config


def _is_timeout(exc: BaseException) -> bool:
    """True if `exc` is (or wraps) a socket-level timeout."""
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return True
    if isinstance(exc, urllib.error.URLError):
        return isinstance(exc.reason, (socket.timeout, TimeoutError))
    return False


class TorrentClient(ABC):
    """Abstract base class for torrent clients"""

    def __init__(self, config: "Config"):
        self.config = config

    @abstractmethod
    async def get_listen_port(self) -> Optional[int]:
        """Get current listening port"""
        pass

    @abstractmethod
    async def set_listen_port(self, port: int) -> bool:
        """Set listening port"""
        pass

    @abstractmethod
    async def set_interface(self, interface_name: str, interface_address: str) -> bool:
        """Set network interface binding"""
        pass


class QBittorrentClient(TorrentClient):
    """qBittorrent client integration"""

    def _request(
        self,
        url: str,
        data: Optional[bytes] = None,
        method: Optional[str] = None,
    ) -> urllib.request.Request:
        """Build a qBittorrent request with optional file-backed Basic auth."""
        request = urllib.request.Request(url, data=data, method=method)
        auth_file = getattr(self.config, "qb_api_auth_file", "")
        if not isinstance(auth_file, str) or not auth_file:
            return request

        try:
            with open(auth_file, encoding="utf-8") as handle:
                credential = handle.readline().rstrip("\r\n")
        except OSError as exc:
            raise RuntimeError(
                "qBittorrent API credential file is not readable"
            ) from exc

        username, separator, password = credential.partition(":")
        if not separator or not username or not password:
            raise ValueError(
                "qBittorrent API credential file must contain username:password"
            )

        token = base64.b64encode(credential.encode("utf-8")).decode("ascii")
        request.add_header("Authorization", f"Basic {token}")
        return request

    async def get_listen_port(self) -> Optional[int]:
        try:
            with urllib.request.urlopen(
                self._request(f"{self.config.qb_api_url}/preferences"),
                timeout=self.config.qb_api_timeout,
            ) as resp:
                prefs = json.loads(resp.read().decode())
                return prefs.get("listen_port")
        except Exception as e:
            log.error(f"Failed to get qBittorrent port: {e}")
            return None

    async def get_connection_status(self) -> Optional[str]:
        """Get libtorrent connection status: 'connected', 'firewalled',
        or 'disconnected'. Returns None on API error.

        Retries once on timeout (qBit's WebUI thread occasionally pauses
        for several seconds under load); only logs ERROR if both attempts
        fail. A single transient timeout is logged at WARNING.

        Note on URL construction: `qb_api_url` ends in `/api/v2/app`
        (the application-namespaced endpoint base used by /preferences
        and /setPreferences). `/transfer/info` is a *sibling* of /app,
        not a child — the full path is `/api/v2/transfer/info`. Wiring
        this as `{qb_api_url}/transfer/info` produces
        `/api/v2/app/transfer/info`, which qBittorrent returns 404 for,
        making the listener health check silently blind and spamming
        `Failed to get qBittorrent connection status: HTTP Error 404`
        in the logs. Strip the trailing `/app` segment before appending.
        """
        api_v2 = self.config.qb_api_url.removesuffix("/app")
        url = f"{api_v2}/transfer/info"
        timeout = self.config.qb_api_timeout

        for attempt in (1, 2):
            try:
                with urllib.request.urlopen(
                    self._request(url), timeout=timeout
                ) as resp:
                    info = json.loads(resp.read().decode())
                    return info.get("connection_status")
            except Exception as e:
                if attempt == 1 and _is_timeout(e):
                    log.warning(
                        f"qBittorrent connection-status timed out "
                        f"after {timeout}s, retrying once"
                    )
                    await asyncio.sleep(1)
                    continue
                log.error(f"Failed to get qBittorrent connection status: {e}")
                return None
        return None

    async def _toggle_port(self, port: int) -> bool:
        """Toggle listen port off/on to force libtorrent to rebind the socket."""
        log.info(f"Toggling port to force listener rebind on {port}")
        try:
            data = urllib.parse.urlencode({
                "json": json.dumps({"listen_port": port - 1})
            }).encode()
            req = self._request(
                f"{self.config.qb_api_url}/setPreferences",
                data=data, method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.config.qb_api_timeout):
                pass

            await asyncio.sleep(2)

            data = urllib.parse.urlencode({
                "json": json.dumps({"listen_port": port})
            }).encode()
            req = self._request(
                f"{self.config.qb_api_url}/setPreferences",
                data=data, method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.config.qb_api_timeout):
                pass

            await asyncio.sleep(3)

            status = await self.get_connection_status()
            if status and status != "disconnected":
                log.info(f"Port rebind successful (status: {status})")
                return True

            log.warning(f"Port rebind may have failed (status: {status})")
            return False

        except Exception as e:
            log.error(f"Port toggle failed: {e}")
            return False

    async def set_listen_port(self, port: int) -> bool:
        try:
            current = await self.get_listen_port()
            if current == port:
                log.debug(f"qBittorrent port unchanged ({port})")
                return True

            log.info(f"Updating qBittorrent port: {current} -> {port}")

            data = urllib.parse.urlencode({
                "json": json.dumps({"listen_port": port})
            }).encode()

            req = self._request(
                f"{self.config.qb_api_url}/setPreferences",
                data=data, method="POST"
            )

            with urllib.request.urlopen(req, timeout=self.config.qb_api_timeout):
                pass

            await asyncio.sleep(3)

            new_port = await self.get_listen_port()
            if new_port != port:
                log.warning("qBittorrent port update may have failed")
                return False

            # Verify the listener is actually bound, not just the config value
            status = await self.get_connection_status()
            if status == "disconnected":
                log.warning(f"Port {port} set but listener not bound (status: disconnected), toggling to force rebind")
                return await self._toggle_port(port)

            log.info(f"qBittorrent port updated successfully (status: {status})")
            return True

        except Exception as e:
            log.error(f"Failed to set qBittorrent port: {e}")
            return False

    async def set_interface(self, interface_name: str, interface_address: str) -> bool:
        """Set qBittorrent network interface binding"""
        try:
            # Get current settings
            with urllib.request.urlopen(
                self._request(f"{self.config.qb_api_url}/preferences"),
                timeout=self.config.qb_api_timeout,
            ) as resp:
                prefs = json.loads(resp.read().decode())

            current_iface = prefs.get("current_network_interface", "")
            current_addr = prefs.get("current_interface_address", "")

            if current_iface == interface_name and current_addr == interface_address:
                log.debug(f"qBittorrent interface unchanged ({interface_name})")
                return True

            log.info(f"Updating qBittorrent interface: {current_iface} -> {interface_name}")

            data = urllib.parse.urlencode({
                "json": json.dumps({
                    "current_network_interface": interface_name,
                    "current_interface_name": interface_name,
                    "current_interface_address": interface_address
                })
            }).encode()

            req = self._request(
                f"{self.config.qb_api_url}/setPreferences",
                data=data, method="POST"
            )

            with urllib.request.urlopen(req, timeout=self.config.qb_api_timeout):
                pass

            log.info(f"qBittorrent interface updated to {interface_name} ({interface_address})")
            return True

        except Exception as e:
            log.error(f"Failed to set qBittorrent interface: {e}")
            return False
