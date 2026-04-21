#!/usr/bin/env python3
"""
MOLE DNS over TLS Server - Standalone entry point for running in namespace

Usage:
    ip netns exec vpn python3 -m mole_pkg.services.dns_main [options]
"""

import argparse
import asyncio
import json
import os
import signal
import sys
from pathlib import Path

# Add parent to path for imports when run standalone
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mole_pkg.services.dns import DOTServer
from mole_pkg.services.dns_upstream import DOT_PROVIDERS
from mole_pkg.utils import log


class StandaloneConfig:
    """Minimal config object for standalone DNS server"""

    def __init__(self, args):
        self.dot_bind = args.bind
        self.dot_port = args.port
        self.dot_upstream = args.upstream
        # Pre-parse the comma-separated list form so DOTServer's pool sees a
        # clean list without re-splitting.
        self.dot_upstreams = [
            u.strip() for u in (args.upstream or '').split(',') if u.strip()
        ] or ['cloudflare']
        self.dot_custom_server = args.custom_server or ""
        self.dot_block_ads = args.block_ads
        self.dot_block_malware = args.block_malware
        self.dot_block_tracking = args.block_tracking
        self.dot_caching = args.caching
        self.dot_cache_ttl = args.cache_ttl
        self.dot_update_period = args.update_period
        self.dot_pool_size = args.pool_size
        self.dot_query_timeout = args.query_timeout
        self.dot_query_retries = args.query_retries
        self.dot_retry_backoff_ms = args.retry_backoff_ms
        self.dot_enabled = True
        self.state_dir = args.state_dir


async def _stats_writer_loop(server: DOTServer, state_dir: Path,
                             interval: float = 1.0) -> None:
    # api_main runs as a separate process and cannot read DOTServer state
    # directly, so snapshot it to a file it can poll.
    stats_path = state_dir / "dns_stats.json"
    tmp_path = state_dir / "dns_stats.json.tmp"
    while True:
        try:
            stats = server.get_stats()
            stats['cache_entries'] = stats.pop('cache_size', 0)
            stats['cache_size_bytes'] = sum(
                len(v[0]) for v in server._cache.values()
            )
            tmp_path.write_text(json.dumps(stats))
            os.replace(tmp_path, stats_path)
        except Exception as e:
            log.warning(f"Failed to write dns_stats.json: {e}")
        await asyncio.sleep(interval)


async def main_async(args):
    """Async main entry point"""
    config = StandaloneConfig(args)
    server = DOTServer(config, netns="vpn")

    # Setup signal handlers for graceful shutdown
    loop = asyncio.get_event_loop()
    shutdown_event = asyncio.Event()

    def signal_handler():
        log.info("DNS server received shutdown signal")
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    # Start server in background
    server_task = asyncio.create_task(server.start())
    stats_task = asyncio.create_task(
        _stats_writer_loop(server, Path(args.state_dir))
    )

    # Wait for shutdown signal
    await shutdown_event.wait()

    # Cleanup
    await server.stop()
    for task in (server_task, stats_task):
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    log.info("DNS server stopped")


def main():
    parser = argparse.ArgumentParser(
        description="MOLE DNS over TLS Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Upstream providers: {', '.join(DOT_PROVIDERS.keys())}

Examples:
  %(prog)s --bind 127.0.0.1 --port 53 --upstream cloudflare
  %(prog)s --bind 0.0.0.0 --upstream quad9 --block-ads --block-malware
"""
    )

    parser.add_argument("--bind", default="127.0.0.1",
                        help="Address to bind to (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=53,
                        help="Port to listen on (default: 53)")
    parser.add_argument("--upstream", default="cloudflare",
                        help="Upstream DNS provider (default: cloudflare). "
                             "Accepts a comma-separated list for failover, "
                             "e.g. 'cloudflare,quad9'.")
    parser.add_argument("--custom-server",
                        help="Custom DoT server (ip:port) when upstream includes 'custom'")
    parser.add_argument("--block-ads", action="store_true", default=False,
                        help="Enable ad blocking")
    parser.add_argument("--block-malware", action="store_true", default=False,
                        help="Enable malware blocking")
    parser.add_argument("--block-tracking", action="store_true", default=False,
                        help="Enable tracking blocking")
    parser.add_argument("--caching", action="store_true", default=True,
                        help="Enable DNS response caching (default: enabled)")
    parser.add_argument("--no-caching", action="store_false", dest="caching",
                        help="Disable DNS response caching")
    parser.add_argument("--cache-ttl", type=int, default=0,
                        help="Max cache TTL in seconds (0 = use response TTL)")
    parser.add_argument("--update-period", type=int, default=86400,
                        help="Blocklist update period in seconds (default: 86400)")
    parser.add_argument("--state-dir", default="/var/lib/mole",
                        help="State directory for caching blocklists")
    parser.add_argument("--pool-size", type=int, default=2,
                        help="Persistent TLS connections per upstream (default: 2)")
    parser.add_argument("--query-timeout", type=float, default=2.0,
                        help="Per-attempt upstream query timeout, seconds (default: 2.0)")
    parser.add_argument("--query-retries", type=int, default=2,
                        help="Retries per upstream before failover (default: 2)")
    parser.add_argument("--retry-backoff-ms", type=int, default=200,
                        help="Backoff between retries in milliseconds (default: 200)")

    args = parser.parse_args()

    log.info(f"Starting DNS over TLS server on {args.bind}:{args.port}")
    log.info(f"Upstream: {args.upstream}")

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
