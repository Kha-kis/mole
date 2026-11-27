# Cold Observation Retry: Isolated Result

Status: isolated implementation accepted; two independent findings corrected and
focused re-review reports no new findings. No production
activation, publication, merge or release is established by this report.

## Repair

The observer reports only fixed, allowlisted outcomes. Failure messages echo
the current nonce and round ID; unknown, extra-field, mismatched and zero-exit
failure replies cannot become transient retry permission. Socket timeout and
network-unreachable outcomes are the only retryable reasons. TLS, malformed,
oversized and conflicting responses remain terminal. One network-failed adapter
does not hide a valid other adapter.

Cold-connect can make at most three rounds for the same installed Attempt and
generation. A retry requires successful probe cleanup, revocation and CLOSED
kernel readback, with fresh round/fence identity and observation. The absolute
deadline is the earlier of the existing candidate deadline and the configured
readiness timeout, including backoff and per-round work. Ordinary refresh,
legacy and PIA behavior have no added retry loop.

The worker leaves one second of reply margin inside the ten-second parent cap.
A two-timeout virtual-clock case reproduced the old exact-deadline race before
this margin was added. Request, headers and body share an absolute per-adapter
deadline of at most five seconds. A temporary POSIX timer in the dedicated
synchronous child bounds slow-drip/blocking calls; it refuses a pre-existing
timer and restores the old handler. The controller's signals/timers are not
changed. No external timeout cap grows.

Repeated cancellation and disconnect failure during failed revocation remain
terminal; they cannot be normal candidate-retry results or replace an existing
cancellation with an ordinary exception. Fixed diagnostics contain no underlying
exception messages or helper payloads.

## Verification

- Typed observer cases were red before implementation, then green.
- Cold transient-then-success and three-round cases were red against the prior
  one-shot path; they now pass with fresh rounds and unchanged Attempt identity.
- CLOSED readback tests were red before the new bounded verifier, then green.
- Three cleanup/cancellation combined-failure regressions were red before their
  corrections, then green.
- Full suite before independent review: 611 tests, 10.774 seconds, OK.
- Review reproduced cancellation first raised during fallback disconnect and a
  fourteen-second multi-phase HTTP case that lost its typed timeout. Both were
  corrected after red tests, with a real timer-bound check and timer-ownership
  preservation coverage. Full corrected suite: 615 tests, 11.212 seconds, OK.
- Focused Ruff checks pass for the changed validation/gate modules and new tests.
  The broader orchestrator still has five pre-existing unused-import/variable
  findings; this is not a clean full-project lint/type-check claim.
- Whitespace check passes. Python 3.13 was run; Python 3.8 execution is not claimed.
- Independent follow-up passed 28 focused tests, three supplemental timer checks,
  Ruff and whitespace checks. The reviewer did not repeat the final full suite;
  its 615-test result above is the implementing agent's fresh run.

## Remaining Gates

The live forced-failure recovery gate remains failed, and the underlying provider
transport cause remains unproven. These isolated tests do not recreate provider
availability or constitute a successful production recovery. Independent review
is complete; publication approval and a separately approved controlled live trial
remain. Keep this change local until publication is approved.
The sequential-bootstrap partial-result risk remains deferred as scoped.
