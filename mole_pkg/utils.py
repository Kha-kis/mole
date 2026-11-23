"""
MOLE Utilities - Logging, state management, and helper functions
"""

import asyncio
import configparser
import json
import logging
import os
import re
import signal
import subprocess
import time
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
    generation: int = 0
    forwarding_ready: bool = False
    port_deadline: float = 0.0
    tunnel_ready: bool = False
    tunnel_deadline: float = 0.0
    client_ready: bool = False
    hook_ready: Optional[bool] = None
    last_error: str = ''


def read_wg_peer_key(config_path: str) -> str:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        with open(config_path) as handle:
            parser.read_file(handle)
        if parser.sections().count('Peer') != 1:
            raise ValueError
        key = parser.get('Peer', 'PublicKey').strip()
        if not key or any(c.isspace() for c in key):
            raise ValueError
        return key
    except (OSError, ValueError, configparser.Error):
        raise ValueError('WireGuard config must contain exactly one intended peer') from None


def handshake_timestamp(output: str, peer_key: str, now: float, not_before: float = 0):
    rows = [row.split() for row in output.strip().splitlines()]
    if len(rows) != 1 or len(rows[0]) != 2 or rows[0][0] != peer_key:
        return None
    try:
        timestamp = int(rows[0][1])
    except ValueError:
        return None
    if timestamp <= 0 or not 0 <= now - timestamp <= 180 or timestamp < not_before:
        return None
    return timestamp


def _process_identity(pid: int) -> str:
    # PID alone can be reused. Bind evidence to this boot and process start tick.
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    start = Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()[19]
    return boot + ':' + start


def write_runtime_readiness(directory: Path, state: VPNState) -> None:
    evidence = {
        'pid': os.getpid(), 'process_identity': _process_identity(os.getpid()),
        'generation': state.generation, 'tunnel_ready': state.tunnel_ready,
        'tunnel_deadline': state.tunnel_deadline, 'forwarding_ready': state.forwarding_ready,
        'port_deadline': state.port_deadline, 'port': state.port,
        'client_ready': state.client_ready, 'hook_ready': state.hook_ready,
        'last_error': state.last_error,
    }
    for name, content in [('runtime_generation', str(state.generation)),
                          ('runtime_readiness.json', json.dumps(evidence))]:
        temporary = directory / (name + '.tmp')
        secure_write_file(temporary, content)
        os.replace(temporary, directory / name)


def read_runtime_readiness(directory: Path) -> dict:
    blocked = dict(connected=False, tunnel_ready=False, forwarding_ready=False,
                   client_ready=False, hook_ready=None, last_error='no_current_evidence', generation=None)
    try:
        evidence = json.loads((directory / 'runtime_readiness.json').read_text())
        generation = int((directory / 'runtime_generation').read_text())
        if type(evidence['pid']) is not int or type(evidence['generation']) is not int:
            return blocked
        if evidence['generation'] != generation or evidence['process_identity'] != _process_identity(evidence['pid']):
            return blocked
        now = time.monotonic()
        tunnel = evidence['tunnel_ready'] is True and now < float(evidence['tunnel_deadline']) <= now + 3600
        forwarding = (tunnel and evidence['forwarding_ready'] is True and
                      now < float(evidence['port_deadline']) <= now + 86400)
        return dict(connected=tunnel, tunnel_ready=tunnel, forwarding_ready=forwarding,
                    client_ready=tunnel and evidence['client_ready'] is True,
                    hook_ready=evidence.get('hook_ready'), last_error=evidence.get('last_error', ''),
                    generation=generation)
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        return blocked


async def async_run_in_netns(cmd: list, netns: str, timeout: float) -> subprocess.CompletedProcess:
    """Own the command's process group until completion, timeout or cancellation."""
    argv = ['ip', 'netns', 'exec', netns] + cmd

    async def drain(task):
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
        return task.result()

    spawn = asyncio.create_task(asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=True))
    try:
        process = await asyncio.shield(spawn)
    except asyncio.CancelledError:
        process = await drain(spawn)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await drain(asyncio.create_task(process.communicate()))
        raise

    output = asyncio.create_task(process.communicate())
    try:
        stdout, stderr = await asyncio.wait_for(asyncio.shield(output), timeout=timeout)
        return subprocess.CompletedProcess(argv, process.returncode,
                                           stdout.decode(errors='replace'),
                                           stderr.decode(errors='replace'))
    except (asyncio.TimeoutError, asyncio.CancelledError):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await drain(output)
        raise


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


def increment_dict_counter(state_dir: Path, name: str, dict_key: str, field: str) -> int:
    """Atomically increment a nested-dict counter persisted as JSON.

    Used for labelled Prometheus counters that need per-(dict_key, field)
    accumulators — e.g. NAT-PMP success/failure counts per VPN country.
    Schema on disk:
        {"NL": {"success": 21184, "failure": 49}, "US": {...}}

    Same single-owner assumption as `increment_counter`: mole increments
    these from one task, so read-modify-write is safe without locking.
    Empty/missing dict_key falls back to "unknown" so we never silently
    drop attempted writes (a connected-but-unlabelled state still counts).
    """
    import json
    if not dict_key:
        dict_key = "unknown"
    path = state_dir / name
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            data = {}
    except (FileNotFoundError, ValueError):
        data = {}
    bucket = data.setdefault(dict_key, {})
    if not isinstance(bucket, dict):
        bucket = {}
        data[dict_key] = bucket
    new_value = int(bucket.get(field, 0)) + 1
    bucket[field] = new_value
    atomic_write_state(state_dir, name, json.dumps(data))
    return new_value


def read_dict_counter(state_dir: Path, name: str) -> dict:
    """Read a JSON dict-counter file back as a plain dict.

    Returns an empty dict on any read/parse failure — readers should treat
    "no file" and "malformed file" identically (i.e. no labelled samples
    to emit) rather than raise into the scrape path.
    """
    import json
    try:
        data = json.loads((state_dir / name).read_text())
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, ValueError):
        return {}


def append_ring_buffer(state_dir: Path, name: str, entry: dict, max_entries: int = 20) -> int:
    """Atomically append `entry` to a JSON-list ring buffer, capped at
    `max_entries`. Returns the new length after truncation.

    Used for per-event state (e.g. recent VPN renewals) where dashboards
    want a "last N" view rather than a counter aggregate. Same single-
    owner assumption as `increment_counter`. Malformed/missing files are
    treated as empty so a corrupted state file can't crash the writer.
    """
    import json
    path = state_dir / name
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, list):
            data = []
    except (FileNotFoundError, ValueError):
        data = []
    data.append(entry)
    if len(data) > max_entries:
        # Drop oldest entries — preserves the newest at the tail.
        data = data[-max_entries:]
    atomic_write_state(state_dir, name, json.dumps(data))
    return len(data)


def read_ring_buffer(state_dir: Path, name: str) -> list:
    """Read a ring-buffer JSON list back; empty list on any failure."""
    import json
    try:
        data = json.loads((state_dir / name).read_text())
        return data if isinstance(data, list) else []
    except (FileNotFoundError, ValueError):
        return []


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
