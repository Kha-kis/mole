"""
MOLE DNS over TLS upstream pool.

Manages persistent, pipelined TLS connections to one or more DoT providers
so DNS queries don't each pay a full TCP + TLS handshake. Supports:

  - multiple upstreams with failover rotation on repeated failure
  - N persistent connections per upstream (configurable via DOT_POOL_SIZE)
  - many in-flight queries per connection, dispatched by DNS message ID
  - bounded per-attempt timeout with retry + backoff
  - xid translation so callers can use any message ID without collision

Not intended for direct use by non-DoT callers. DOTServer drives this.
"""

import asyncio
import itertools
import ssl
import struct
from typing import Dict, List, Optional, Tuple

from ..utils import log


# DoT presets. (ip, port, sni_hostname). This is the canonical definition;
# dns.py re-exports it for backward compatibility with earlier callers.
DOT_PROVIDERS = {
    'cloudflare': ('1.1.1.1', 853, 'cloudflare-dns.com'),
    'cloudflare-family': ('1.1.1.3', 853, 'family.cloudflare-dns.com'),
    'quad9': ('9.9.9.9', 853, 'dns.quad9.net'),
    'quad9-unsecured': ('9.9.9.10', 853, 'dns.quad9.net'),
    'google': ('8.8.8.8', 853, 'dns.google'),
}


def resolve_upstream(name: str, custom_server: str = "") -> Tuple[str, int, str]:
    """Resolve an upstream name (preset or 'custom') to (ip, port, sni).

    For 'custom', reads custom_server in the form 'ip[:port]'.
    """
    key = (name or "").strip().lower()
    if key == 'custom':
        if ':' in custom_server:
            ip, port = custom_server.rsplit(':', 1)
            return (ip.strip(), int(port), ip.strip())
        return (custom_server.strip(), 853, custom_server.strip())
    return DOT_PROVIDERS.get(key, DOT_PROVIDERS['cloudflare'])


class UpstreamExhausted(Exception):
    """Raised when every upstream has failed all retries for a query."""


class _Connection:
    """A single persistent TLS connection to one upstream.

    Owns:
      - a StreamReader/Writer pair (length-prefixed DoT framing)
      - a dedicated read-loop task that dispatches responses by xid
      - a map of outstanding xids -> Futures, plus a writer lock serializing
        the length-prefixed sends
    """

    # Any xid outside 16-bit DNS range is invalid; we allocate modulo 65536.
    _XID_MAX = 0x10000

    def __init__(self, host: str, port: int, sni: str):
        self.host = host
        self.port = port
        self.sni = sni

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._read_task: Optional[asyncio.Task] = None
        self._write_lock = asyncio.Lock()
        self._pending: Dict[int, asyncio.Future] = {}
        self._xid_counter = itertools.count()
        self._connect_lock = asyncio.Lock()
        self._closed = False

    def is_open(self) -> bool:
        return (
            self._writer is not None
            and not self._writer.is_closing()
            and self._read_task is not None
            and not self._read_task.done()
            and not self._closed
        )

    async def ensure_open(self, connect_timeout: float) -> None:
        """Open the connection if it isn't already. Idempotent and re-entrant.

        Refuses to open a connection that has been close()d — callers should
        treat this as a hard failure and not retry on the same connection.
        """
        if self._closed:
            raise ConnectionError("connection closed")
        if self.is_open():
            return
        async with self._connect_lock:
            if self._closed:
                raise ConnectionError("connection closed")
            if self.is_open():  # recheck under lock
                return
            # Clean up any stale halves left from a prior failure
            await self._close_streams()
            ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.host, self.port, ssl=ctx, server_hostname=self.sni
                ),
                timeout=connect_timeout,
            )
            self._reader = reader
            self._writer = writer
            self._read_task = asyncio.create_task(
                self._read_loop(), name=f"dot-read-{self.host}:{self.port}"
            )

    async def query(
        self,
        query_bytes: bytes,
        client_xid: int,
        timeout: float,
    ) -> bytes:
        """Send a query, await response, return response bytes with client_xid.

        Raises on timeout, connection loss, or protocol errors. Callers are
        expected to retry via the pool's rotation logic.
        """
        if len(query_bytes) < 12:
            raise ValueError("DNS query too short")

        await self.ensure_open(connect_timeout=timeout)

        # Allocate a pool-owned xid. 16-bit wrap with collision retry.
        for _ in range(8):
            pool_xid = next(self._xid_counter) % self._XID_MAX
            if pool_xid not in self._pending:
                break
        else:
            # Astronomically unlikely given typical in-flight counts
            raise RuntimeError("exhausted xid space on connection")

        # Splice pool_xid onto query for wire transmission
        framed_query = struct.pack('!H', pool_xid) + query_bytes[2:]

        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[pool_xid] = fut

        try:
            async with self._write_lock:
                if self._writer is None or self._writer.is_closing():
                    raise ConnectionError("connection closed before write")
                self._writer.write(struct.pack('!H', len(framed_query)) + framed_query)
                await self._writer.drain()

            response = await asyncio.wait_for(fut, timeout=timeout)
        except Exception:
            # On timeout/failure, detach our waiter so a late response doesn't
            # resolve a stale Future. The caller will retry on another connection.
            self._pending.pop(pool_xid, None)
            raise
        finally:
            # Future is already removed by _read_loop on success, but ensure
            # we never leak an entry if we bailed early.
            self._pending.pop(pool_xid, None)

        # Splice the caller's original xid back onto the response.
        return struct.pack('!H', client_xid) + response[2:]

    async def _read_loop(self) -> None:
        """Read length-prefixed frames until the connection dies.

        On any error, fails all pending Futures with the exception so waiters
        unblock promptly and retry.
        """
        reader = self._reader
        try:
            while reader is not None:
                length_data = await reader.readexactly(2)
                length = struct.unpack('!H', length_data)[0]
                response = await reader.readexactly(length)
                if len(response) < 2:
                    continue
                xid = struct.unpack('!H', response[:2])[0]
                fut = self._pending.pop(xid, None)
                if fut is not None and not fut.done():
                    fut.set_result(response)
                # Unknown xid → silently drop (late response after caller gave up)
        except asyncio.IncompleteReadError:
            self._fail_pending(ConnectionError("upstream closed connection"))
        except asyncio.CancelledError:
            self._fail_pending(asyncio.CancelledError())
            raise
        except Exception as e:
            self._fail_pending(e)
        finally:
            await self._close_streams()

    def _fail_pending(self, exc: BaseException) -> None:
        """Drain and fail every outstanding waiter."""
        pending, self._pending = self._pending, {}
        for fut in pending.values():
            if not fut.done():
                fut.set_exception(exc)

    async def _close_streams(self) -> None:
        w = self._writer
        self._reader = None
        self._writer = None
        if w is not None and not w.is_closing():
            try:
                w.close()
                await w.wait_closed()
            except Exception:
                pass

    async def close(self) -> None:
        """Close the connection. Idempotent — safe to call multiple times."""
        if self._closed and self._read_task is None and self._writer is None:
            return
        self._closed = True
        if self._read_task is not None and not self._read_task.done():
            self._read_task.cancel()
            try:
                await self._read_task
            except (asyncio.CancelledError, Exception):
                pass
        self._read_task = None
        self._fail_pending(ConnectionError("connection closed"))
        await self._close_streams()


class _UpstreamTarget:
    """One upstream (ip, port, sni) plus its pool of connections.

    We don't "acquire/release" connections; instead we spray queries across
    the pool round-robin. With pipelining, a busy connection isn't blocked
    by in-flight queries — multiple queries just stack on the same stream.
    """

    def __init__(self, name: str, host: str, port: int, sni: str, pool_size: int):
        self.name = name
        self.host = host
        self.port = port
        self.sni = sni
        self.pool_size = max(1, pool_size)
        self._connections: List[_Connection] = [
            _Connection(host, port, sni) for _ in range(self.pool_size)
        ]
        self._rr = itertools.count()

    def pick(self) -> _Connection:
        """Round-robin connection picker."""
        return self._connections[next(self._rr) % len(self._connections)]

    async def close(self) -> None:
        for c in self._connections:
            await c.close()


class UpstreamPool:
    """Pool of pooled TLS connections to one or more DoT upstreams, with
    per-upstream retry + rotation across upstreams on repeated failure.

    Expected usage from DOTServer:

        pool = UpstreamPool(upstreams=['cloudflare','quad9'], ...)
        resp = await pool.query(query_bytes, client_xid)

    `query` raises UpstreamExhausted if every upstream fails all retries.
    """

    def __init__(
        self,
        upstreams: List[str],
        custom_server: str = "",
        pool_size: int = 2,
        query_timeout: float = 2.0,
        query_retries: int = 2,
        retry_backoff_ms: int = 200,
        stats: Optional[dict] = None,
    ):
        if not upstreams:
            upstreams = ['cloudflare']
        self._targets: List[_UpstreamTarget] = []
        for name in upstreams:
            ip, port, sni = resolve_upstream(name, custom_server)
            self._targets.append(
                _UpstreamTarget(name=name, host=ip, port=port, sni=sni,
                                pool_size=pool_size)
            )
        self._query_timeout = max(0.1, float(query_timeout))
        self._query_retries = max(0, int(query_retries))
        self._backoff = max(0, int(retry_backoff_ms)) / 1000.0
        self._stats = stats if stats is not None else {}
        # Pre-seed counter keys so readers (tests, /v1/dns) always see a
        # consistent shape even when the pool has never fired a query.
        for key in ('upstream_queries', 'upstream_errors', 'retries', 'failovers'):
            self._stats.setdefault(key, 0)

    def upstream_info(self) -> List[dict]:
        """Best-effort snapshot of each upstream for /v1/dns reporting.

        The first-listed upstream is always the configured primary; there is
        no sticky "active" state because failover is per-query only.
        """
        out = []
        for i, t in enumerate(self._targets):
            open_count = sum(1 for c in t._connections if c.is_open())
            out.append({
                'name': t.name,
                'host': t.host,
                'port': t.port,
                'pool_size': t.pool_size,
                'open_connections': open_count,
                'primary': (i == 0),
            })
        return out

    async def query(self, query_bytes: bytes, client_xid: int) -> bytes:
        """Try each upstream in order; retry on transient errors.

        Total attempts per call: len(targets) * (retries + 1). Bounded.
        Failover is per-query — the primary upstream is always tried first.
        A transient failure on the primary does NOT permanently divert
        traffic to a secondary.

        Counters incremented during this call:
          upstream_queries: one per attempt (success or failure)
          upstream_errors:  one per failed attempt
          retries:          one per same-upstream retry
          failovers:        one per per-query move to a later upstream
        """
        last_exc: Optional[BaseException] = None
        for upstream_idx, target in enumerate(self._targets):
            if upstream_idx > 0:
                self._stats['failovers'] = self._stats.get('failovers', 0) + 1
                log.debug(
                    f"DoT upstream {self._targets[upstream_idx - 1].name} "
                    f"exhausted, trying {target.name}"
                )
            for attempt in range(self._query_retries + 1):
                conn = target.pick()
                try:
                    self._stats['upstream_queries'] = self._stats.get('upstream_queries', 0) + 1
                    return await conn.query(
                        query_bytes, client_xid, timeout=self._query_timeout,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    last_exc = e
                    self._stats['upstream_errors'] = self._stats.get('upstream_errors', 0) + 1
                    if attempt < self._query_retries:
                        self._stats['retries'] = self._stats.get('retries', 0) + 1
                        if self._backoff:
                            await asyncio.sleep(self._backoff)
                        continue
                    # Out of retries on this upstream; try the next upstream
                    break
        raise UpstreamExhausted(f"all upstreams failed; last error: {last_exc!r}")

    async def close(self) -> None:
        for t in self._targets:
            await t.close()
