# Cached DNS Health Implementation Plan

> Execute natively with test-first changes and independent final review.

**Goal:** Detect fresh-query failures and identify validation failure stages.
**Architecture:** Random resolver questions, strict bounded reply validation,
and fixed stage codes propagated through existing fail-closed control flow.
**Tech Stack:** Existing Python standard-library implementation and unittest.
**Spec:** ./assessment.md; original specs/001-proton-pool-recovery contracts.

## Global Constraints

- No production changes, external account operations or new dependencies.
- Existing timeout, cancellation, permission and approved-pool rules unchanged.
- No raw helper output or exception messages in public diagnostics.

## Review Focus

- Cached positive answers must not mask upstream failure.
- Local filtered NXDOMAIN must not count as an upstream health result.
- Negative authority records and compression pointers must be bounded.
- Classified errors must retain fail-closed and cancellation behavior.
- Cleanup errors must remain visible without leaking inner exceptions.

## Task 1: DNS freshness

- [x] Add failing real-resolver and wire-response regression tests.
- [x] Verify the old implementation fails those tests.
- [x] Add bounded DNS validation and fresh names; keep resolver policy intact.
- [x] Run DNS-specific tests and the full suite.

## Task 2: Validation diagnostics

- [x] Add failing tests for stage reporting, secrecy and revocation.
- [x] Add allowlisted stage errors at existing component boundaries.
- [x] Verify targeted tests and the full suite.

## Task 3: Acceptance

- [x] Obtain independent code review and resolve confirmed findings.
- [x] Repeat the real cache reproduction with the repaired source.
- [x] Record fix/test results and retained-worktree lifecycle.
- [x] Leave production and release state unchanged.
