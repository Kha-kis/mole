# Bug Fix: Bounded Provider And Lifecycle Operations

- Slug: blocking-provider-operations (resolved from approved assessment context)
- Fixed: 2026-11-23
- Assessment: ./assessment.md
- Status: applied (isolated source only; independent review pending)

## Summary

Blocking Proton SDK calls now run in stoppable helpers. Session jobs are
serialized, operate on private staged copies and are adopted atomically only
after successful current-generation completion with an unchanged live session.
Network bootstrap, switching, hooks and client-service commands are bounded;
candidate preparation preserves installed-tunnel monitoring and forwarding.

## Changes

| File | Change | Notes |
| --- | --- | --- |
| `mole_pkg/utils.py` | Generic owned async command runner | Launch/input/wait share a deadline; kill/reap on timeout or cancellation. |
| `mole_pkg/providers/proton.py` | Staged SDK transaction owner; async latency/API paths | Authentication 120 s; API jobs 45 s; latency 3 s, at most ten concurrent. |
| `mole_pkg/providers/proton_worker.py` | Restricted SDK dispatch | Private pipes; saved-session compatibility preserved; fixed errors. |
| `mole_pkg/network.py` | Async runtime helpers and fail-closed startup ordering | DROP before external link/NAT; checked endpoint reconciliation. |
| `mole_pkg/network_worker.py` | Owned bootstrap process | Outer 120 s; strict mutating-command checks and 10 s command budgets. |
| `mole_pkg/mole.py` | Async lifecycle and installed/candidate separation | WireGuard/hooks 30 s; ordinary commands 10 s; one generation transition per switch. |
| `tests/test_owned_commands.py` | Real-child regressions | Private input, backpressure, launch timeout, repeated cancellation and reaping. |
| `tests/test_proton_worker.py` | Offline SDK process regressions | Heartbeat, serialization, timeout/cancellation, stale session/generation, fixed errors and latency. |
| `tests/test_bounded_lifecycle.py` | Lifecycle/policy regressions | Installed monitoring/lease maintenance, command failure, hook timeout, fail-closed ordering. |

Existing fixtures were adapted only where synchronous mocks no longer matched
the runtime boundary. An older invalidate-on-registration-failure expectation
was intentionally replaced: a failed candidate now leaves the verified old
tunnel intact, rather than claiming the candidate is ready.

## Evidence And Deviations

Three implementation commits: `57eabbf`, `c2856df`, `990b17a`.
Failure-first tests were observed for missing owned-command/SDK interfaces,
candidate relabelling, missing async lifecycle boundaries, late DROP ordering,
malformed worker response and the double generation increment. The complete
suite passes 490 tests before independent review. Baseline warnings remain.

No production changes, live provider requests, tracker edits, push or release.
PIA provider API internals and actual Python 3.8 runtime testing remain outside
this extension. Process creation/reaping delayed by the OS can extend cleanup
beyond an operation deadline; ownership is retained rather than abandoning a child.

## Independent Review Corrections

The independent review identified cancellation swallowed during timeout cleanup,
queued SDK jobs inheriting a newer generation, and mapping repair targeting a
rejected candidate instead of the installed server. A fourth saved-preference
finding was regraded Important because successful stickiness must survive a
restart. Each received a failing regression before correction; all four now pass
and the complete suite passes 494 tests. No minor finding is deferred.

The source fix is applied and reviewed, but this is not production acceptance.
