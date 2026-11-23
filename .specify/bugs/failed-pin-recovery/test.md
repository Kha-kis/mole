# Bug Verification: Failed-Pin Recovery

- Slug: failed-pin-recovery
- Tested: 2026-11-23
- Assessment: ./assessment.md
- Fix: ./fix.md
- Result: partial

The original repeated failed-pin reproduction selects the second approved
endpoint after recording failure. Ordering, physical duplicates/cooldowns,
fresh raw-provider resolution, unavailable/outside pins and saved/manual policy
bypasses pass. Overlapping triggers share one owner. Mapping-only degradation,
one recovery budget, bounded exhaustion/backoff, restoration, cancellation and
cleanup pass. Strict pins work across country fallback lists.

Checks: `python3 -m unittest discover -s tests -v` passes 462 tests, exit 0.
The fresh independent reviewer reported seven findings; all received reproducing
tests and corrections. No minor finding was deferred. No second review was used
as a substitute for those regression checks.

The baseline three unclosed-file warnings and unawaited `main_async` warning
remain. No hooks are registered. Live failover and tracker ASN acceptance were
not exercised. Synchronous provider/setup work remains an approved follow-up.

Recommendation: retain the reviewed source; do not deploy until that extension
and the separate live-network gates pass.
