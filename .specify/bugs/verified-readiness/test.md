# Bug Verification: False Tunnel Readiness

- Slug: verified-readiness
- Tested: 2026-11-23
- Assessment: ./assessment.md
- Fix: ./fix.md
- Result: partial

The original connection-without-handshake reproduction now returns false.
Intended-peer/attempt freshness, failed/malformed handshakes, tunnel-bound HTTPS,
one/all failed targets, HTTP denial, deadline/cancellation and installed-identity
regressions pass. Interface-only API health is rejected. Runtime evidence rejects
truncation, wrong generation/identity, actual owner exit and expired leases.

Checks: `python3 -m unittest discover -s tests -v` passes 462 tests, exit 0.
Both entrypoints and Python 3.8 syntax checks pass. Independent review's endpoint
identity and client-generation findings received failure-first corrections.

The existing three unclosed-file warnings and one unawaited `main_async` warning
remain. No hooks are registered. Actual tunnels, DNS and tracker acceptance were
not exercised; version smoke checks are not live runtime acceptance.

Recommendation: retain the stricter semantics; hold deployment pending the
approved blocking-operation extension and live-network acceptance.

## Bounded-Operations Addendum - 2026-11-23

The SDK/lifecycle extension is implemented in isolated source and independently
reviewed, with failure-first corrections. The full suite passes 494 tests. See
`../blocking-provider-operations/test.md` for current evidence and limits.
Live acceptance remains separate; no deployment was performed.
