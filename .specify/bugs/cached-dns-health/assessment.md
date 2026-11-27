# Cached DNS health and opaque validation failures

- Verdict: valid, reproduced using the real resolver and probe.
- Approved scope: isolated repair and tests; no production activation.

## Proposed Remediation

Use a fresh 128-bit random label under example.com for each resolver probe.
Validate the transaction, complete echoed question, flags and record framing.
Accept an IPv4 answer or a well-formed negative response with SOA authority;
reject empty synthesized blocklist responses, failures and truncation. Ordinary
resolver caching and filtering stay unchanged. Preserve the existing bounded
probe timeout and configured resolver path.

Classify validation failures using fixed stage identifiers only. Preserve
explicit denial, cancellation, revocation and disconnect behavior. Do not log
exception messages, helper output, request data or credentials. Distinguish
bootstrap/admission/observation/cleanup, transport, authorizer/evidence and
controller policy/round/grant/readback boundaries.

## Files likely to change

- mole_pkg/validation_worker.py, mole_pkg/validation.py, mole_pkg/mole.py.
- mole_pkg/dns_health.py (bounded wire-format validation only).
- tests/test_dns_health.py, tests/test_validation.py,
  tests/test_validated_recovery.py.

## Tests to add or update

Real cached resolver with dead upstream; repeated probes use different names;
positive and SOA-negative replies work; malformed, truncated, wrong-question,
wrong-ID, SERVFAIL and synthetic empty replies fail. Classified failures still
revoke, cancellation propagates and injected secret strings never reach logs.

## Risks & Considerations

This does not fix or explain the original provider transport outage. The live
acceptance gate remains failed. No firewall widening, timeout increases,
dependency addition, server-list change, service restart or release is included.

## Approaches

Approved: repair the reproduced defect and improve diagnostics in isolation.
Diagnostics-only was considered but leaves the confirmed recovery blind spot.
Direct public-resolver checks bypass the configured resolver and are unsuitable.
