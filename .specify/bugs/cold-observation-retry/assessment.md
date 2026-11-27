# Cold Observation Retry Assessment

Verdict: reproduced availability weakness, not an admission bypass or a proven
explanation of the provider outage. The original recovery acceptance gate is
still failed. Owner approved the isolated repair and tests on November 27, 2026.
Publication and production activation remain separate gates.

## Evidence

Validated cold-connect invokes validation once. If the first observation fails,
the controller revokes permission, the candidate is marked failed and selection
advances. Remaining candidate allocation is not used for another observation.
Legacy readiness repeats transport checks up to its configured deadline.
An offline reproduction supplies a first observation failure followed by a valid
second observation; current cold-connect returns false without requesting the
second. Independent review confirms this control flow.

This does not promise a ninety-second readiness window: the candidate allocation
also covers registration and setup. Both fixed adapters work in current read-only
checks, but those checks do not recreate the failed endpoint/admission boundary.
Neither a future retry succeeding nor the original provider cause is established.

## Approaches

Recommended: classify observation outcomes, then retry only explicitly transient
network failures during cold-connect. Keep all existing authorization boundaries,
absolute budgets and candidate cooldown policy.

Diagnostics-only is lower change risk but leaves premature candidate failure.
Retrying every false result is rejected: the boolean conflates explicit denial,
malformed/conflicting evidence, cancellation and enforcement/cleanup failure.
Broader server discovery or changing approved servers is outside this repair.

## Proposed Design

- Keep the installed candidate, Attempt identity and generation during retries.
  Every retry has a fresh ValidationRound/fence and fresh bound observations.
- Limit cold validation to the earliest of the existing candidate/cycle deadline
  and configured VPN_READY_TIMEOUT, measured from the start of cold validation.
  Keep each validation round at most twenty seconds and its observation at most
  ten seconds. Use at most three rounds with at most one-second backoff, capped
  by remaining time. Do not extend deadlines on retry.
- Introduce only fixed internal failure reasons. Retry socket connection/timeouts
  known to be transient, not arbitrary exceptions or an untyped boolean failure.
  Never expose response bodies, exception messages, addresses or helper input.
- Explicit denial, TLS verification failure, malformed or contradictory evidence,
  policy/identity withdrawal, cancellation, cleanup and enforcement failures are
  terminal for this candidate. A failed result can never grant permission.
- Before retry, verify cleanup succeeded and the owned guard is CLOSED. Recheck
  process, generation, installed peer and current candidate authorization before
  accepting fresh evidence. Failure of CLOSED verification aborts recovery.
- Start the existing refresh loop only after cold validation succeeds. Do not
  add retries to ordinary refresh, widen firewall rules, change approved pools,
  clear credentials or modify external tracker authorization.
- Keep legacy and PIA behavior unchanged. Preserve the existing aggregate
  readiness error and public API compatibility. No new runtime dependencies.

## Deferred Observation

Bootstrap resolves two hosts sequentially within a shared three-second process
budget. A slow second lookup can discard a usable first result. Independent
review identifies this control-flow risk; it has not been exercised and is not
included in the proposed cold-retry implementation.

## Acceptance

Test transient-then-success, persistent failure/deadline exhaustion, explicit
denial, malformed/conflicting evidence, TLS failure, cancellation, cleanup/CLOSED
failure, policy/generation changes and one fresh identity per retry. Require
red-before-green evidence, the full suite and independent review. No live
activation, merge or release is authorized by isolated test success.
