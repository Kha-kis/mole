#!/usr/bin/env python3
"""
MOLE DNS over TLS Server - Standalone entry point for running in namespace

Usage:
    ip netns exec vpn python3 -m mole_pkg.services.dns_main [options]
"""

import argparse
import asyncio
import signal
import sys
from pathlib import Path

# Add parent to path for imports when run standalone
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mole_pkg.services.dns import DOTServer, DOT_PROVIDERS
from mole_pkg.utils import log


class StandaloneConfig:
    """Minimal config object for standalone DNS server"""

    def __init__(self, args):
        self.dot_bind = args.bind
        self.dot_port = args.port
        self.dot_upstream = args.upstream
        self.dot_custom_server = args.custom_server or ""
        self.dot_block_ads = args.block_ads
        self.dot_block_malware = args.block_malware
        self.dot_block_tracking = args.block_tracking
        self.dot_caching = args.caching
        self.dot_cache_ttl = args.cache_ttl
        self.dot_update_period = args.update_period
        self.dot_enabled = True
        self.state_dir = args.state_dir


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

    # Wait for shutdown signal
    await shutdown_event.wait()

    # Cleanup
    await server.stop()
    server_task.cancel()
    try:
        await server_task
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
                        choices=list(DOT_PROVIDERS.keys()) + ["custom"],
                        help="Upstream DNS provider (default: cloudflare)")
    parser.add_argument("--custom-server",
                        help="Custom DoT server (ip:port) when --upstream=custom")
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
