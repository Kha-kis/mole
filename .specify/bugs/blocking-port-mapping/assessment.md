# Bug Assessment: Blocking And Unbounded Port Mapping

- **Slug**: blocking-port-mapping (agent-generated)
- **Created**: 2026-11-23
- **Source**: pasted user report and approved recovery design
- **Verdict**: valid
- **Severity**: high

## Report

Forwarding failures delay health checks and recovery, leaving dependent apps
without connectivity longer than expected.

## Symptom

Async mapping methods invoke synchronous subprocesses with no explicit timeout.
Expected: bounded operations without blocking the event loop or orphaning children.

## Reproduction

1. Replace the namespace command with a synthetic 120 ms blocking mapping reply.
2. Schedule a 10 ms heartbeat and await UDP/TCP mapping refresh.
3. Heartbeat runs only after about 252 ms. Exercised without real NAT-PMP or
   production changes. Source confirms no explicit subprocess timeout.

## Suspected Code Paths

- `mole_pkg/providers/proton.py:_request_port_mapping`, `_renew_port_mappings`,
  `setup_port_forward`, `refresh_port_forward` run synchronous commands.
- `mole_pkg/utils.py:run_cmd`, `run_in_netns` wait synchronously.
- `mole_pkg/mole.py:_keepalive_loop` shares that event loop with watchdog.

## Root Cause Hypothesis

High confidence: async declarations do not make child-process waits nonblocking.

## Proposed Remediation

Add an async namespace-command helper with deadline, process ownership and
kill/reap on cancellation. Await mappings, serialize writers and reject stale
results across tunnel generations. Adopt only matching TCP/UDP valid leases.

**Files likely to change**: `mole_pkg/utils.py`, `mole_pkg/providers/proton.py`,
`mole_pkg/mole.py`, `mole_pkg/services/api_main.py`, `tests/test_utils.py`,
`tests/test_port_forward_renewal.py`, new `tests/test_recovery.py`.

**Tests to add**: stalled synthetic child, heartbeat responsiveness, deadline and
cancellation reaping, mismatched/expired/short leases, rotation, concurrent
refresh and slow client synchronization.

## Risks & Considerations

Old work must not publish stale state. Preserve existing client locking.
Healthy VPN egress continues during mapping degradation. Broader blocking SDK
operations must be considered in review, not assumed fixed by this helper or
silently expanded into a provider rewrite.

## Open Questions

None blocking. Actual child timeout/cancellation reproduction belongs to fix/test.
