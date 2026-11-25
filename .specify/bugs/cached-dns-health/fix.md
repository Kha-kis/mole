# Bug Fix: Fresh DNS health and validation stage diagnostics

- Slug: cached-dns-health.
- Fixed: 2026-11-25.
- Assessment: ./assessment.md.
- Status: applied in isolation; not deployed.

## Summary

Fresh randomized resolver questions cannot reuse a previous positive cache
entry. Replies require the matching question, complete wire framing and either
an IPv4 answer or SOA-backed negative result. Ordinary filtering/cache behavior
is unchanged. Fixed validation stage identifiers locate failures without exposing
helper output or inner exception text; existing aggregate readiness is retained.

## Changes

| File | Change |
| --- | --- |
| mole_pkg/dns_health.py | Bounded DNS response and compression validation |
| mole_pkg/validation_worker.py | Fresh random questions through configured resolver |
| mole_pkg/validation.py | Allowlisted stage errors at existing boundaries |
| mole_pkg/mole.py | Fixed stage/outcome logs with original fail-closed handling |
| tests/test_dns_health.py | Real resolver/cache and malformed wire regressions |
| tests/test_validation.py | Stage propagation, secrecy, timeout and cancellation |
| tests/test_validated_recovery.py | Logging with permission revocation |
| specs/001-proton-pool-recovery/contracts/validation.md | Diagnostic/freshness contract |

## Local Verification

- Original DNS tests: nine failing assertions/subtests, including real cached
  false health. Repaired DNS tests: all four test methods pass.
- Original diagnostics tests: four failures; repaired validation tests pass.
- Full baseline: 562 tests pass with a private temporary directory.
- Final repaired suite after review corrections: 578 tests pass.
- A read-only fresh probe through the existing VPN resolver returns healthy.
- Whitespace/error check: `git diff --check` passes.
- Existing baseline warnings remain: a mock DNS future exception, unclosed test
  files and an unawaited mocked coroutine. They are not new regressions.
- No production install, restart, permission change, server-list change,
  credential operation, release or merge was performed.

## Deviations from Assessment

None. The original transport outage remains unexplained; this fixes a reproduced
health-check defect and diagnostic opacity, not provider availability.

## Follow-ups

- Independent review identified four issues. Unrelated record ownership and
  malformed CNAME acceptance were reproduced with five failing subtests, then
  repaired by owner/alias-chain and bounded RDATA checks. Nested deadline-stage
  loss was reproduced in two failing test methods, then repaired while retaining
  the cancellation object. The loopback test now uses run_in_executor and passes
  with to_thread unavailable. The final full suite passes after these corrections.
- Risk identified at this checkpoint: cancellation together with failed probe-rule cleanup can
  replace CancelledError with the cleanup exception. This repair preserves that
  prior behavior; it does not establish combined-failure cancellation safety.
  The subsequent isolated correction is recorded in
  [cancelled probe cleanup](../cancelled-probe-cleanup/fix.md).
- Existing static type errors outside changed lines remain. The installed
  Bandit launcher is broken, so no successful Bandit run is claimed. Runtime
  tests used Python 3.13; Python 3.8 itself was not run.
- Select an integration path separately; no public push or merge is included.
- Keep the earlier production acceptance gate failed until a separately
  coordinated live trial passes. Synthetic tests are not provider acceptance.
