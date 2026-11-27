# Cold Observation Retry Implementation Plan

> Execute natively with test-first changes and one independent final review.
> Status: isolated implementation and independent review complete November 27, 2026.

**Goal:** Avoid abandoning a cold candidate after one transient network failure.
**Architecture:** Fixed observation reasons, verified CLOSED enforcement and fresh
same-candidate validation rounds within unchanged absolute deadlines.
**Tech Stack:** Existing Python standard library and unittest, Python 3.8+.
**Spec:** ./assessment.md and specs/001-proton-pool-recovery/contracts/validation.md.

## Global Constraints

- No production changes, new provider/ASN permissions or account operations.
- Existing per-round twenty-second and observation ten-second caps unchanged.
- At most three cold rounds and one-second bounded backoff; no deadline reset.
- No raw helper output/exception messages or private deployment details.
- No snapshots, network allocations or additional VPN sessions for tests.

## Review Focus

- A permanent failure must not be recast as a transient network failure.
- A failed cleanup or unverified CLOSED guard must prevent another round.
- Expired and replaced attempt identities must not authorize fresh work.
- Cancellation must propagate after owned helper cleanup and revocation.
- Shared deadlines must include bootstrap, observation, authorization and backoff.

## Task 1: Classify Observation Outcomes

Files: mole_pkg/validation_worker.py, mole_pkg/validation.py,
tests/test_validation.py, new tests/test_observation_failures.py.

- [x] Write failing cases for transient socket failures, TLS verification failure,
  malformed/oversized/conflicting replies, invalid reason injection and success.
- [x] Verify old code fails the classification expectations.
- [x] Add fixed reason-only propagation without changing grant/denial behavior.
- [x] Verify targeted tests and helper nonzero/deadline/cancellation coverage.

## Task 2: Retry Cold Validation Safely

Files: mole_pkg/mole.py, mole_pkg/network.py,
tests/test_validated_recovery.py, tests/test_validation_gate.py,
new tests/test_cold_validation.py.

- [x] Bring the failing cold-connect reproduction into focused regression tests.
- [x] Add fail-closed, deadline, cancellation, cleanup, policy and identity cases.
- [x] Add bounded verified-CLOSED readback to the existing gate interface.
- [x] Retry only typed transient observation failures, with fresh round identities,
  the same installed candidate and the earliest absolute cold/candidate deadline.
- [x] Verify non-transient failures do not retry and refresh starts only on success.

## Task 3: Validate And Review

- [x] Run the full suite using private temporary storage under the QA workspace.
- [x] Run whitespace/lint checks; distinguish existing baseline findings.
- [x] Obtain independent review, reproduce and correct confirmed findings.
- [x] Update the validation contract and fix report with exact proof boundaries.
- [x] Record isolated acceptance; keep the failed live gate unchanged.
- [ ] Only after review/verification, update the existing public PR if the owner
  approves publication; no merge, release or production activation.
