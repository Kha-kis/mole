"""
MOLE qBittorrent Service - Torrent client integration
"""

import asyncio
import json
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from typing import Optional, TYPE_CHECKING

from ..utils import log

if TYPE_CHECKING:
    from ..config import Config


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

    async def get_listen_port(self) -> Optional[int]:
        try:
            with urllib.request.urlopen(
                f"{self.config.qb_api_url}/preferences", timeout=5
            ) as resp:
                prefs = json.loads(resp.read().decode())
                return prefs.get("listen_port")
        except Exception as e:
            log.error(f"Failed to get qBittorrent port: {e}")
            return None

    async def get_connection_status(self) -> Optional[str]:
        """Get libtorrent connection status (connected/firewalled/disconnected)"""
        try:
            with urllib.request.urlopen(
                f"{self.config.qb_api_url}/transfer/info", timeout=5
            ) as resp:
                info = json.loads(resp.read().decode())
                return info.get("connection_status")
        except Exception as e:
            log.error(f"Failed to get qBittorrent connection status: {e}")
            return None

    async def _toggle_port(self, port: int) -> bool:
        """Toggle listen port off/on to force libtorrent to rebind the socket."""
        log.info(f"Toggling port to force listener rebind on {port}")
        try:
            data = urllib.parse.urlencode({
                "json": json.dumps({"listen_port": port - 1})
            }).encode()
            req = urllib.request.Request(
                f"{self.config.qb_api_url}/setPreferences",
                data=data, method="POST"
            )
            with urllib.request.urlopen(req, timeout=5):
                pass

            await asyncio.sleep(2)

            data = urllib.parse.urlencode({
                "json": json.dumps({"listen_port": port})
            }).encode()
            req = urllib.request.Request(
                f"{self.config.qb_api_url}/setPreferences",
                data=data, method="POST"
            )
            with urllib.request.urlopen(req, timeout=5):
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

            req = urllib.request.Request(
                f"{self.config.qb_api_url}/setPreferences",
                data=data, method="POST"
            )

            with urllib.request.urlopen(req, timeout=5):
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
                f"{self.config.qb_api_url}/preferences", timeout=5
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

            req = urllib.request.Request(
                f"{self.config.qb_api_url}/setPreferences",
                data=data, method="POST"
            )

            with urllib.request.urlopen(req, timeout=5):
                pass

            log.info(f"qBittorrent interface updated to {interface_name} ({interface_address})")
            return True

        except Exception as e:
            log.error(f"Failed to set qBittorrent interface: {e}")
            return False
