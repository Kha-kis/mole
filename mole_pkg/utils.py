"""
MOLE Utilities - Logging, state management, and helper functions
"""

import logging
import os
import re
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import Config


def setup_logging(quiet: bool = False) -> logging.Logger:
    """Setup logging configuration"""
    level = logging.WARNING if quiet else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger("mole")


# Global logger instance
log = logging.getLogger("mole")


@dataclass
class VPNState:
    """Current VPN connection state"""
    token: Optional[str] = None
    token_expires: Optional[datetime] = None
    server_ip: Optional[str] = None
    server_hostname: Optional[str] = None
    server_country: Optional[str] = None
    server_vip: Optional[str] = None
    peer_ip: Optional[str] = None
    port: Optional[int] = None
    port_payload: Optional[str] = None
    port_signature: Optional[str] = None
    port_expires: Optional[datetime] = None
    connected: bool = False


def run_cmd(cmd: list, check: bool = True, env: dict = None) -> subprocess.CompletedProcess:
    """Run a shell command"""
    return subprocess.run(cmd, capture_output=True, text=True, check=check, env=env)


def secure_write_file(path: Path, content: str, mode: int = 0o600) -> None:
    """Write a file with restricted permissions (secure for sensitive data)"""
    # Convert Path to string if needed
    path_str = str(path)
    # Open with O_CREAT|O_WRONLY|O_TRUNC and explicit mode
    fd = os.open(path_str, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
    try:
        os.write(fd, content.encode('utf-8'))
    finally:
        os.close(fd)


def atomic_write_state(state_dir: Path, name: str, content: str) -> None:
    """Atomically write a small state file (rename-after-write).

    Used for plain-text state files like counters and timestamps that the
    api_main subprocess polls. The temp-file + os.replace pattern means a
    reader never sees a partially-written value.
    """
    tmp = state_dir / (name + '.tmp')
    final = state_dir / name
    tmp.write_text(content)
    os.replace(tmp, final)


def increment_counter(state_dir: Path, name: str) -> int:
    """Atomically increment a state-file counter and return the new value.

    Counters are persisted as plain integer text files so they survive a
    mole.service restart. Concurrent writers are not expected — mole has
    a single owner per counter — so a simple read-increment-rename is
    sufficient.
    """
    path = state_dir / name
    try:
        current = int(path.read_text().strip())
    except (FileNotFoundError, ValueError):
        current = 0
    new_value = current + 1
    atomic_write_state(state_dir, name, str(new_value))
    return new_value


def sanitize_for_log(text: str, max_length: int = 200) -> str:
    """Sanitize text for logging by removing sensitive patterns and truncating"""
    if not text:
        return text
    # Mask patterns that look like tokens, API keys, or base64 secrets
    # Token pattern: alphanumeric strings of 20+ chars
    text = re.sub(r'\b[A-Za-z0-9_-]{32,}\b', '[REDACTED]', text)
    # Base64 patterns (long sequences ending in = or ==)
    text = re.sub(r'\b[A-Za-z0-9+/]{20,}={0,2}\b', '[REDACTED]', text)
    # Password/token in JSON
    text = re.sub(r'"(password|token|secret|key|auth)"\s*:\s*"[^"]*"', r'"\1": "[REDACTED]"', text, flags=re.IGNORECASE)
    # Truncate if too long
    if len(text) > max_length:
        text = text[:max_length] + "...[truncated]"
    return text


def run_in_netns(cmd: list, netns: str, check: bool = True, env: dict = None) -> subprocess.CompletedProcess:
    """Run a command inside a network namespace"""
    return run_cmd(["ip", "netns", "exec", netns] + cmd, check=check, env=env)


class VPNProvider(ABC):
    """Abstract base class for VPN providers"""

    def __init__(self, config: "Config", state: VPNState):
        self.config = config
        self.state = state

    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate with the VPN provider and get a token"""
        pass

    @abstractmethod
    async def get_server(self) -> bool:
        """Get server information for connection"""
        pass

    @abstractmethod
    async def register_wireguard(self) -> bool:
        """Register WireGuard keys and get connection config"""
        pass

    @abstractmethod
    async def setup_port_forward(self) -> bool:
        """Setup port forwarding"""
        pass

    @abstractmethod
    async def refresh_port_forward(self) -> bool:
        """Refresh/keepalive port forwarding"""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name"""
        pass
