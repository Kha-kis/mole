# Bug Assessment: Rejected Hard-Coded Proton Client Identity

- **Slug**: proton-client-identity (agent-generated)
- **Created**: 2026-11-23
- **Source**: pasted user report and prior verified compatibility repair
- **Verdict**: valid
- **Severity**: high

## Report

Proton rejects obsolete client identity; repeated renewal cannot correct it.

## Symptom

Released source hard-codes 4.19.0. A separately verified deployment correction
uses 4.19.1. Expected: preserve that correction, add a validated override and
classify compatibility rejection without hammering fresh credential login.

## Reproduction

1. Inspect constants and constructor regression in released source.
2. It supplies `linux-vpn@4.19.0` and the matching UA.
3. Prior private incident checks verified rejection and recovery with 4.19.1;
   no fresh provider authentication was performed for this assessment.
4. Fix-stage tests must reproduce rejection with a synthetic API response.

## Suspected Code Paths

- `mole_pkg/providers/proton.py:PROTON_CLIENT_VERSION`, `ProtonSessionWrapper`
  construction/load/refresh/authenticate and `ProtonProvider.authenticate`.
- `mole_pkg/config.py:validate_config` has no override validation.
- `tests/test_proton_client_identity.py` expects 4.19.0.

## Root Cause Hypothesis

High confidence in missing source correction/override. Provider acceptance is
externally controlled; no identity string is guaranteed permanent.

## Proposed Remediation

Default to verified 4.19.1 and validate `PROTON_CLIENT_VERSION`. Use fixed app/UA
formats for new and loaded sessions without changing saved credentials/cookies.
Classify rejection and back off. Never guess versions, disable TLS verification
or auto-download fixes as recovery behavior.

**Files likely to change**: `mole_pkg/config.py`, `mole_pkg/providers/proton.py`,
`tests/test_config.py`, `tests/test_proton_client_identity.py`, `config.example`,
`README.md` and generic failure/status reporting if required.

**Tests to add**: default/valid/malformed override, equal new/load identity,
saved credential preservation, rejection classification, bounded retries and
secret-safe diagnostics.

## Risks & Considerations

Mock rejection is not live provider acceptance. Normal live renewal is a rollout
gate. Broader SDK blocking findings require recorded scope review, not assumption.

## Open Questions

None blocking. Do not report mocked provider tests as live authentication checks.
