# Bug Assessment: Tunnel Readiness Without A Handshake

- **Slug**: verified-readiness (agent-generated)
- **Created**: 2026-11-23
- **Source**: pasted user report and approved recovery design
- **Verdict**: valid
- **Severity**: high

## Report

VPN-dependent applications stop communicating while Mole remains active and
reports a connection after repeated recovery attempts.

## Symptom

Interface configuration is treated as connected without a peer handshake.
Expected: a fresh intended-peer handshake and tunnel-routed public egress.

## Reproduction

1. Construct Mole with synthetic state and mocked namespace commands.
2. Make interface setup and public endpoint ping succeed; provide no handshake.
3. Call `_connect_vpn`: it returns true and sets connected without querying
   handshakes. Exercised in a non-mutating assessment probe.

## Suspected Code Paths

- `mole_pkg/mole.py:_connect_vpn` claims connected after setup.
- `_check_health` checks later and tolerates missing handshake command/output.
- `mole_pkg/services/api_main.py:_get_status` independently reconstructs health.
- `mole_pkg/utils.py:VPNState` carries readiness and lease state.

## Root Cause Hypothesis

High confidence: setup and readiness are conflated. The public server address
has a route outside the tunnel, so its ping cannot prove encrypted traffic.

## Proposed Remediation

Bounded, attempt-specific intended-peer handshake plus public-egress checks;
invalidate readiness during recovery; reject missing/malformed/stale evidence.
Either of two configured probes may succeed. Do not require endpoint ICMP.
Share semantics with status reporting and retain compatible API fields.

**Files likely to change**: `mole_pkg/mole.py`, `mole_pkg/utils.py`,
`mole_pkg/config.py`, `mole_pkg/services/api_main.py`, `tests/test_mole.py`,
`tests/test_api_main.py`, new `tests/test_recovery.py`, `config.example`, `README.md`.

**Tests to add**: missing/zero/stale/future/foreign peer, command failure, empty
output, fresh handshake with egress, ignored endpoint ICMP, one/all failed probes,
startup deadline and state invalidation.

## Risks & Considerations

Stricter semantics affect monitoring. Probe failure does not prove provider fault.
No real interface was changed; network-level validation remains a rollout gate.

## Open Questions

None blocking. Probe mechanics and additive field names are plan-owned details.
