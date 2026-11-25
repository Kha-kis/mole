# Bug Fix: Preserve cancellation during probe cleanup failure

- Slug: cancelled-probe-cleanup.
- Date: 2026-11-25.
- Assessment: ./assessment.md.
- Status: applied in isolation; independent review found no blockers.

## Changes

The observer retains its original cancellation while attempting existing
cleanup. Rule-removal or group-removal failure during cancellation emits only a
fixed cleanup warning, marks the stage and rethrows cancellation. Ordinary
cleanup errors still raise. Group removal never runs after unverified rule
removal. No new timeout, retry path or production operation is introduced.

## Verification

- Before repair, two subtests fail: both cleanup errors replace cancellation.
- After repair, both return the original cancellation object.
- Repeated cancellation preserves a cancelled outcome and retains the group.
- A real owned helper is killed and reaped before failed rule cleanup completes.
- Total timeout remains a validation failure classified at cleanup.
- Controller tests verify revocation, interface-down fallback when revocation
  fails, cleared readiness and no torrent-service restart or normal retry result.
- Full suite: 585 tests pass. Existing baseline mock/resource warnings remain.
- Focused Ruff checks and `git diff --check` pass.
- Independent reviewer ran 38 targeted tests and checked repeated cancellation
  through observe/validate, cleanup ordering and controller safety. No blocking
  correctness or security findings were reported.

## Deferred Minor

BasedPyright flags the dynamic `_mole_validation_stage` attribute assignment,
matching an existing pattern in the stage context. This is a non-blocking
typing diagnostic, not a runtime failure or configured project gate. Full
static checking is not clean, and Bandit's installed launcher is unavailable.

## Limits

No kernel firewall rules or production services were changed. This combined
failure is tested with fake gate operations plus a real disposable child, not
by causing a production cleanup failure. This does not explain the original
provider transport outage, and the earlier live acceptance gate remains failed.
