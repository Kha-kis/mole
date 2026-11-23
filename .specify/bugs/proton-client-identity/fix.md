# Fix: Proton Client Identity

Status: applied (isolated source only; no live rollout).

## Root Cause And Changes

Released source used an obsolete fixed identity. The default is now 4.19.1,
with strict numeric major.minor.patch validation and an explicit override.
Both session creation and loading use the same fixed identity format; saved
credentials and cookies remain unchanged. Structured rejection code 5003 stops
password fallback. Provider exceptions are not printed on these paths.

Files: config.py, providers/proton.py, config.example and client identity tests.

## Verification

Before the repair, the version assertion and saved-session rejection test failed;
the new configuration/constructor interfaces were absent. Regression checks
cover invalid overrides, new/loaded identity parity, credential preservation,
bounded rejection and secret-safe logs. Full suite result is recorded in the
execution ledger and final test report.

## Deviations

Only structured compatibility code 5003 is permanent here, not every HTTP 422.
Other failures remain bounded and generic. No speculative versions or TLS
verification changes are introduced. Live provider acceptance is a rollout gate.

## Independent Review Corrections

The optional Proton SDK import no longer prevents PIA-only runtime startup.
Original credential, tool and provider-setting validation remains reachable.
Both cases have failure-first subprocess/configuration regressions.
