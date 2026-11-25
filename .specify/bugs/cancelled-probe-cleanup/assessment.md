# Cancelled probe cleanup

- Verdict: confirmed. Two regression subtests demonstrate that rule-removal or
  cgroup-removal errors replace the original cancellation with a cleanup error.
- Scope: isolated follow-up to the validated recovery review; no production
  activation, account operations, permission changes or timeout changes.

## Design and Remediation

Preserve the original cancellation through best-effort existing probe cleanup.
If cleanup fails during that cancellation, record only a fixed cleanup warning
and stage on the cancellation, retain the failed resource for diagnosis, and
rethrow cancellation. Do not remove a group while rule removal is unverified.
Non-cancelled cleanup failures remain errors. Existing controller revocation and
interface-down fallback must still execute, and no next recovery attempt may be
started by converting cancellation into a normal false result.

Masking cleanup errors silently is unsuitable; replacing cancellation with an
ordinary retryable error is the reproduced bug. No cleanup timeout extension or
new shutdown supervisor is necessary for this bounded correction.

## Plan

- [x] Reproduce both cleanup failures with unchanged source.
- [x] Preserve cancellation and report cleanup through fixed diagnostics.
- [x] Test repeated cancellation, ordinary errors, total timeout and controller
  revocation/interface-down behavior.
- [x] Run the full suite, obtain independent review, record evidence.

## Files

mole_pkg/validation.py; tests/test_validation_cleanup.py;
tests/test_validated_recovery.py; validation contract and this bug record.
