# Bug Assessment: Recovery Reuses A Failed Pinned Endpoint

- **Slug**: failed-pin-recovery (agent-generated)
- **Created**: 2026-11-23
- **Source**: pasted user report and approved recovery design
- **Verdict**: valid
- **Severity**: high

## Report

Automatic recovery repeatedly chooses the same unresponsive endpoint.

## Symptom

Full renewal selects the pin again without failure-aware policy. Expected:
opt-in approved-list failover, strict backward-compatible pinning otherwise.

## Reproduction

1. Supply a synthetic pin and two eligible synthetic candidates.
2. Call `get_server` for consecutive recovery attempts after a simulated failure.
3. Both select the first endpoint. Exercised with mocked lists and no networking.

## Suspected Code Paths

- `mole_pkg/providers/proton.py:get_server` prefers pin/saved server.
- `mole_pkg/mole.py:_watchdog_loop`, `_full_renewal`, `_restart_watcher_loop`
  lack shared failure-aware serialized recovery policy.
- `mole_pkg/config.py` lacks the approved-list contract.
- `mole_pkg/services/api_main.py` must not permit manual policy bypass.

## Root Cause Hypothesis

High confidence: recovery repeats selection rather than recording failures.
Several logical names may also share one failed physical address.

## Proposed Remediation

Explicit ordered approved list, strict validation, endpoint cooldown, bounded
attempts/backoff and serialized renewal. A member pin is the initial preference;
saved state cannot reorder/bypass policy. Disabled mode preserves current selection.
Failed tunnels block; healthy VPN plus unavailable mappings is degraded, not
permission for direct traffic or unlimited reconnects.

**Files likely to change**: `mole_pkg/config.py`, `mole_pkg/providers/proton.py`,
`mole_pkg/mole.py`, new `mole_pkg/recovery.py`, `mole_pkg/services/api_main.py`,
`tests/test_config.py`, `tests/test_providers.py`, new `tests/test_recovery.py`,
`config.example`, `README.md`.

**Tests to add**: failover success, exhaustion, invalid/empty list, outside pin,
saved/manual bypass, duplicate endpoint, cooldown, ordered wrap, disabled-mode
compatibility, concurrent renewal and degraded mapping recovery.

## Risks & Considerations

Opt-in list policy is an explicitly approved repair capability, not an automatic
change for every strict-pin user. Logical names do not guarantee stable ASN;
validate deployment separately and never alter tracker authorization automatically.

## Open Questions

None blocking. Plan must spell out numerical budgets and rollout boundaries.
