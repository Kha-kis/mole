"""Bounded namespace bootstrap, owned as one process group by the supervisor."""
import json
import subprocess
import sys
from types import SimpleNamespace

from . import network


def bounded_command(cmd, check=True, env=None):
    # These probes legitimately return nonzero for absent links/rules. Every
    # mutating bootstrap command must succeed before external connectivity.
    probe = cmd[:3] == ['ip', 'link', 'show'] or (cmd[:1] == ['iptables'] and '-C' in cmd)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                          check=not probe, env=env)


def main():
    try:
        config = SimpleNamespace(**json.load(sys.stdin))
        network.run_cmd = bounded_command
        network.run_in_netns = lambda cmd, netns, check=True, env=None: bounded_command(
            ['ip', 'netns', 'exec', netns] + cmd, check, env)
        # Namespace probes are prefixed; their nonzero status is not used in
        # bootstrap, so the strict mutating-command check is intentional.
        network.setup_namespace(config)
    except Exception:
        print('namespace setup failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
