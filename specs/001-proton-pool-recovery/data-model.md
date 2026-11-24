# Validated Recovery Data Model

Canonical constraints for plan.md, contracts and implementation tasks.

## Candidate

JSON-compatible dictionary, retaining existing provider field names:

- `Candidate.name`: approved logical name, existing name syntax, maximum 64 chars.
- `Candidate.hostname`: physical hostname, fallback logical hostname; ASCII DNS
  name, maximum 253 chars, no whitespace/credentials/URL components.
- `Candidate.entry_ip`: canonical global IPv4 string; cooldown/destination key.
- `Candidate.exit_ip`: optional canonical global IPv4 advertised by the provider;
  metadata only, never authorization proof.
- `Candidate.public_key`: strict base64 encoding of exactly 32 bytes.
- `Candidate.port`: integer 51820 for this feature; no arbitrary protocol fallback.
- `Candidate.tier`: integer 0..2, at most current effective account entitlement.
- `Candidate.features`: nonnegative integer bitmask; bit 4 required for P2P.
- `Candidate.load`: finite number 0..100, ordering hint, never health evidence.
- `Candidate.country`: two uppercase ASCII letters; metadata, not authorization.

Selection order: configured logical-name priority, then entry IP/public key.
Evidence identity: `(entry_ip, port, public_key)`; attempted/cooldown identity:
`entry_ip`. Conflicting keys for the same destination in one discovery response
make that destination unusable; do not guess which key is current.

## DiscoveryRecord

- `DiscoveryRecord.schema`: exactly integer 1; unknown versions rejected.
- `DiscoveryRecord.scope`: lowercase 64-hex SHA-256 of canonical API origin,
  current SDK session UID, configured account-identifier digest/tier and
  certificate public-identity digest. Verified entitlement is stored within
  that scope rather than requiring a live lookup to compute the scope. No raw
  account ID, token, password or private key is stored here.
- `DiscoveryRecord.entitlement_tier`: integer 0..2 from a successful `/vpn/v2`
  MaxTier lookup, restricted by configured tier; missing/invalid data is rejected.
- `DiscoveryRecord.entitlement_observed_wall`: finite positive original epoch
  seconds of successful entitlement lookup, not cache reread time.
- `DiscoveryRecord.observed_wall`: finite positive epoch seconds; future values
  rejected without clock-skew grace.
- `DiscoveryRecord.boot_id`: opaque local boot identifier, 1..128 ASCII chars.
- `DiscoveryRecord.observed_mono`: finite nonnegative monotonic seconds from that
  boot; future values in the same boot rejected.
- `DiscoveryRecord.candidates`: zero to 512 valid Candidate records. Zero is
  permitted only from a valid nonempty global catalogue withdrawing eligibility.

File limit 4 MiB, regular file, owner is the running service's effective UID,
mode 0600, parent 0700; reject symlinks/unsafe parents. Normalize only approved
candidates; do not persist the full global catalogue. Expiry is 86,400 seconds
by default and hard maximum; zero disables fallback. Compare wall age and, within
the same boot, monotonic age, taking the greater; either invalid age rejects.
Across boots wall time is trusted only if not before observation. Newer entitlement
restrictions invalidate the record; new session/certificate identities invalidate scope. Token refresh alone
with unchanged session UID does not. Missing binding components disable fallback.
The timestamps denote successful discovery/entitlement, never cache reread or
failed refresh. Both ages must fit max_age; fresh publication needs both live
observations. Discovery alone cannot extend old entitlement. A newer known
entitlement restriction invalidates conflicting older records.

Known credential/certificate/compatibility rejection creates a separate private
`discovery_blocked.json` marker bound to scope and typed reason. It never expires
into approval. Only successful online revalidation clears it; restart does not.
Use cache-equivalent safe paths/modes and atomic publication. Write pending before
the online operation; do not send it if that write fails. A known transient may
clear its own pending marker only when no earlier rejection existed. Unknown
completion/crash remains blocked. This avoids learning an unpersistable rejection
and later forgetting it at restart.

## RejectionRecord

- `RejectionRecord.scope`: same 64-hex base identity scope as DiscoveryRecord.
- `RejectionRecord.transaction_id`: fresh 64-hex random transaction identity.
- `RejectionRecord.kind`: pending, credentials_rejected, compatibility or
  certificate_rejected; every value blocks fallback until an authorized clearing.
- `RejectionRecord.observed_wall`: finite positive epoch observation time, for
  diagnostics only, never an expiry into authorization.

A late/cancelled transaction cannot remove another transaction's record. Clearing
a pending record on transient failure must preserve any preceding blocked state.
If a blocked/pending record already exists, do not overwrite it with a new
pending record; revalidation may remove it only after online success. A transient
result may clear pending only when that operation created it from an absent record.

## Attempt

- `Attempt.process_identity`: current boot/PID-start identity from existing utils.
- `Attempt.generation`: current nonnegative integer generation.
- `Attempt.nonce`: 64 lowercase hex chars from 32 random bytes, unique per attempt.
- `Attempt.candidate`: one canonical Candidate, immutable during validation.
- `Attempt.policy_revision`: 64-hex digest of effective approvals/configuration;
  changing it invalidates prior evidence and closes the gate.
- `Attempt.deadline`: finite monotonic deadline owned by the current process.

Do not persist/reuse an Attempt across process restart. Only the orchestrator may
publish it. Before any candidate change, close/revoke the old attempt first.

## ValidationRound

- `ValidationRound.id`: fresh 64-hex random identity; not reused for refresh.
- `ValidationRound.attempt`: exact immutable current Attempt identity.
- `ValidationRound.acknowledged_mono`: monotonic time after successful kernel
  acknowledgement of creating that round's deadline fence.
- `ValidationRound.fence_max_ttl`: exactly 90 seconds, established before fresh
  observation. The separate grant operation cannot create or refresh this fence.

Workload permission requires BOTH that round's unexpired fence and grant. Proof
must cover acknowledged_mono + fence_max_ttl, a conservative upper bound on actual
fence expiry. A late grant therefore cannot extend proof lifetime, even if the
controller dies before revocation. Each new round requires new observation and
authorization tied to its ID; old proof must never populate a new round's grant.

## ExitEvidence

- `ExitEvidence.attempt`: exact process/generation/nonce/candidate/policy identity.
- `ExitEvidence.round_id`: exact current ValidationRound.id.
- `ExitEvidence.exit_ip`: freshly observed canonical global IPv4 from the bound
  helper, not Candidate.exit_ip or an earlier connection.
- `ExitEvidence.allowed`: strict boolean from a validated authorizer response.
- `ExitEvidence.asns`: sorted unique positive 32-bit integers, maximum 8;
  an authorizer can return empty only for a denied/unavailable result.
- `ExitEvidence.observed_wall`: current finite epoch seconds.
- `ExitEvidence.expires_wall`: greater than observation and at most 120 seconds
  later; authorizer proof cannot outlive its own supporting authorization record.
- `ExitEvidence.reason`: one of authorized, denied, unavailable, invalid_evidence.

Convert accepted wall expiry to a local monotonic deadline once. Do not extend
it on reread. Both evidence deadlines must cover the round fence upper bound;
otherwise reject that round without opening. Gate maximum TTL is 90 seconds,
with a new round every 30 seconds. No packet activity may refresh permission.

## RecoveryHealth

- `RecoveryHealth.authorization_ready`: strict current-evidence boolean.
- `RecoveryHealth.gate_open`: boolean only after actual rule/permit verification.
- `RecoveryHealth.dns_ready`: null before a probe, otherwise a current boolean.
- `RecoveryHealth.discovery_source`: live, cache or none.
- `RecoveryHealth.cache_age_seconds`: null or finite nonnegative age.
- `RecoveryHealth.next_retry_in_seconds`: null or finite nonnegative delay.
- `RecoveryHealth.recovery_reason`: none, connecting, transient_discovery,
  no_eligible_candidates, pool_cooldown, transport_failed, authorization_denied,
  authorization_unknown, enforcement_unavailable, dns_failed, forwarding_failed,
  client_sync_failed, credentials_rejected or compatibility_rejected.
- `RecoveryHealth.workload_ready`: verified transport AND authorization AND open
  gate AND working DNS AND required forwarding/client synchronization.

Legacy mode adds fields as not-applicable/null where appropriate; it must not
pretend the new authorization gate is installed. Existing status field semantics
remain documented separately. Tracker acceptance is never inferred from these
fields or a generic hook result.
