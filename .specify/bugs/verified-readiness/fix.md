# Fix: Verified Readiness

Status: applied to isolated source; not live-network accepted.

## Root Cause And Changes

Interface setup and an endpoint ping did not prove encrypted traffic. Readiness
now requires an intended-peer, nonzero, recent handshake new to the connection
attempt plus TLS/HTTP transport forced through the WireGuard interface. Either
configured public probe can succeed, including HTTP denial; there is no endpoint
ICMP dependency. All probes share a monotonic candidate deadline and cancellation
propagates. Connection state is invalidated before interface replacement.

Atomic evidence carries process/boot identity, generation and monotonic validity.
API health and metrics reject missing, truncated, stale-process, mismatched or
expired evidence; separate tunnel, forwarding and client readiness are additive.
The legacy run command now delegates to the maintained modular orchestrator.

## Tests And Verification

Regressions cover missing/zero/stale/future/foreign/old handshakes, ambiguous peer
configuration, credentials/private probe URLs, failed targets, interface-bound
HTTPS, denial responses, deadlines/cancellation, generation changes, original
no-handshake connection reproduction and API interface-only false positives.
Full suite evidence is in the execution ledger and final verification report.

## Deviations

WireGuard timestamps have one-second precision. The lower bound is the whole
second immediately before successful interface creation; wg-quick must create
the new interface, so a same-second first handshake is valid. Requiring the next
whole second would incorrectly reject a new connection until its next handshake.
Legacy runtime delegation is necessary to meet the both-entrypoints contract;
unrelated legacy command implementations are not rewritten.

## Independent Review Corrections

Installed endpoint/peer/generation are tracked separately from selection, so a
failed registration cannot relabel the old live interface as a new connection
or lose the endpoint to remove from firewall/routes. Health requires that
installed identity. Client publication checks generation as well as address/port.
Actual owner-process exit invalidates runtime evidence. These cases were added
as regressions; stale endpoint and client publication failures were observed
before correction.
