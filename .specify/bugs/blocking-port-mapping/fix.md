# Fix: Bounded Asynchronous Mapping

Status: applied (isolated source only).

## Root Cause And Changes

NAT-PMP used synchronous unbounded subprocess calls from async methods.
The new async namespace helper owns a process group, kills and reaps on timeout
or cancellation, and preserves cancellation. Proton awaits each mapping with a
10-second child limit. A single writer lock plus generation check prevents late
publication. Matching UDP/TCP leases use the earlier monotonic expiry; invalid,
partial, expired and mismatched results are not adopted. Wall-clock changes
cannot extend the in-process lease. Keepalive timing respects short leases,
including initial setup while client synchronization is still running.

## Tests And Evidence

Real synthetic children exercise heartbeat, timeout and cancellation cleanup.
The original stale-generation behavior was observed accepting an old result;
it is now rejected. Mapping regressions cover concurrent writers, protocol
mismatch, expiry during the second reply, clock jumps, short initial leases and
slow client API work. Full results are in the execution ledger/test report.

## Deviations And Follow-ups

The keepalive checks new lease timing at most once per second instead of sleeping
through initial setup. Other synchronous provider SDK calls remain an explicit
Task 4 audit item. No real namespace, NAT-PMP server or production client was
modified by these synthetic tests.

## Independent Review Corrections

Port changes invalidate client readiness. Slow client synchronization/listener
repair is supervised separately from tunnel monitoring and renewal ownership.
The port endpoint and metric consume the current atomic lease, never a stale
saved port. Expiry, mismatched historical files and client-generation races have
failure-first regressions. Additional real-child tests cover cancellation during
spawn and descendant termination; the owned leader is reaped, orphan zombies
remain the operating system's reaping responsibility.
