# Bug Verification: Bounded Provider And Lifecycle Operations

- Slug: blocking-provider-operations
- Tested: 2026-11-23
- Assessment: ./assessment.md
- Fix: ./fix.md
- Result: partial

## Summary

The offline SDK stall reproduction no longer blocks the monitoring heartbeat.
Source checks pass; independent review and live acceptance are not yet complete.

## Checks Performed

| Check | Command / Action | Result | Notes |
| --- | --- | --- | --- |
| Post-fix reproduction | Delayed offline SDK through `_fetch_servers` with concurrent 10 ms heartbeat | pass | 11.93 ms heartbeat; 285.54 ms total operation. Original heartbeat was 161 ms. |
| Owned command tests | `python3 -m unittest discover -s tests -p test_owned_commands.py -v` | pass | Five real-child tests, private input/environment, blocked input timeout and launch cancellation. |
| Namespace child tests | `python3 -m unittest discover -s tests -p test_async_commands.py -v` | pass | Six existing real-child tests, including descendant termination. |
| SDK worker tests | `python3 -m unittest discover -s tests -p test_proton_worker.py -v` | pass | Twelve tests with offline SDK and actual helper processes. |
| Lifecycle tests | `python3 -m unittest discover -s tests -p test_bounded_lifecycle.py -v` | pass | Eleven tests; no real namespace or firewall commands. |
| Full regression | `python3 -m unittest discover -s tests -v` | pass | 490 tests before independent review, exit 0. |
| Firewall regression | `python3 -m unittest discover -s tests -p test_killswitch_policy.py -v` | pass | Five tests. |
| Provider regression | `python3 -m unittest discover -s tests -p test_providers.py -v` | pass | 25 tests, including PIA compatibility. |
| Entrypoints | `python3 ./mole --version`, `python3 -m mole_pkg --version` | pass | Both report v0.5.1; no release/version bump. |
| Syntax | AST parsing with `feature_version=(3,8)` | pass | 23 source files; not an actual Python 3.8 interpreter run. |
| Whitespace | `git diff --check` | pass | No errors. |
| Actual Python 3.8 / live network | Not exercised | skipped | Requires separate environment/rollout approval. |

## Output Excerpts

`Ran 490 tests in 8.159s` / `OK`.
`{"heartbeat_ms": 11.93, "operation_ms": 285.54, "offline": true}`.

## Residual Risks

- Independent extension review is in progress at this checkpoint.
- Baseline unclosed-file ResourceWarnings and unawaited `main_async`
  RuntimeWarnings remain. Warning attribution/count can vary with garbage collection.
- No real Proton login, namespace setup, external port check or tracker call
  was made. PIA's provider API implementation was not rewritten.
- Owned process cleanup waits for OS creation/reaping; a kernel delay can exceed
  the requested operation budget without abandoning child ownership.
- All original test names remain except the intentionally replaced
  registration-failure expectation: preserve verified old-tunnel readiness while
  refusing to report a failed candidate as the installed connection.

## Recommendation

Hold installation until independent review findings are resolved. Then seek
separate controlled rollout approval and perform the live-network gates. Source
tests alone do not establish tracker authorization or sustained connectability.

## Independent Review Addendum - 2026-11-23

The fresh review of `089d14c..990b17a` identified four defects. All four were
reproduced as failing tests and corrected in one fix pass. Cancellation during
timeout cleanup now propagates after reaping; queued SDK jobs cannot inherit a
new generation; mapping repair explicitly resolves the installed endpoint; and
verified switches persist their server preference.

Post-fix full regression: `Ran 494 tests in 8.117s` / `OK`, exit 0. The baseline
DNS mock-future diagnostic also remains, alongside the warnings listed above.
Optional unconfigured BasedPyright/Ruff runs were not clean; Bandit's launcher
could not import its package. No clean static-analysis/security-scan claim is made.

Result remains **partial** solely for unperformed live-network/actual-interpreter
acceptance, not an outstanding Important review finding. No second reviewer was
used in place of RED-to-GREEN regressions. Keep the source branch and proceed
only through a separately approved live rollout. No push/release/deployment.
