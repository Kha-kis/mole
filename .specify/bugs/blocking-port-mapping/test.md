# Bug Verification: Blocking Port Mapping

- Slug: blocking-port-mapping
- Tested: 2026-11-23
- Assessment: ./assessment.md
- Fix: ./fix.md
- Result: partial

The original delayed-heartbeat symptom no longer reproduces through the provider
path with two real synthetic children. Timeout/cancellation, cancellation during
spawn, owned-leader reaping and descendant termination pass. Mapping agreement,
old-generation rejection, expiry, clock jumps, short leases and slow client work
pass. Atomic current-port/metric publication and expiry also pass.

Checks: `python3 -m unittest discover -s tests -v` passes 462 tests, exit 0;
five firewall tests and 25 provider tests pass. Baseline warnings remain: three
unclosed test files and one unawaited `main_async` warning. No hooks are registered.

Live NAT-PMP and external reachability were not exercised. Other provider/setup
blocking was audited and is in an approved follow-up scope. Orphan zombies are
reaped by the operating system, not by this process's child-wait interface.

Recommendation: synthetic repair holds; complete the follow-up and live gates.

## Bounded-Operations Addendum - 2026-11-23

The SDK/lifecycle extension is implemented in isolated source and independently
reviewed, with failure-first corrections. The full suite passes 494 tests. See
`../blocking-provider-operations/test.md` for current evidence and limits.
Live acceptance remains separate; no deployment was performed.
