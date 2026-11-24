# Validated Proton Pool Recovery Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans or
> superpowers:subagent-driven-development after owner design approval. Execute
> the test-first tasks in tasks.md; do not infer production rollout approval.

**Goal:** Recover through an approved pool without allowing workload traffic
through a candidate before its actual exit is authorized.

**Architecture:** Extend the provider, pure recovery policy and single-owner
orchestrator. Add validated discovery persistence and an opt-in kernel gate
with a probe-only cgroup and bounded external authorization contract. Tracker
registration remains independently owned by the host.

**Tech Stack:** Python 3.8+ standard library and existing Proton SDK; Linux
WireGuard/iptables, plus nftables and cgroup v2 for the new validated mode.

**Spec:** [spec.md](spec.md), owner approved 2026-11-24. This design awaits
approval; no feature branch, executable edits, merge, release or deployment yet.

## Global Constraints

- Preserve fail-closed networking, torrent files/process, PIA and both entrypoints.
- `PROTON_RECOVERY_MODE=legacy|validated`, default legacy. Validated mode requires
  Proton, explicit failover and a configured exit validator; legacy is unchanged.
- No new Python runtime dependency; missing enforcement support blocks activation.
- Keep the 900-second cooldown floor and at most three distinct attempts/cycle.
- New recovery cycle deadline: 300 seconds including preparation; each candidate
  gets at most 90 seconds and a fair share of remaining time/remaining attempts.
- Discovery cache maximum/default age is 24 hours; zero disables fallback.
- No private deployment data in public artifacts. No QA snapshots or live fixtures.

## Review Focus

- Early traffic, existing connections, root/nobody clients and proxies must be
  stopped by real kernel tests, not merely flags or application settings.
- Controller death must expire permission without userspace intervention.
- Offline recovery must exercise credential preparation, not just cache.load().
- Fresh withdrawals and name/key aliases must not resurrect old candidates.
- Routing-data ASN and tracker ASN can disagree; qualification must stop on an
  unexplained mismatch, not call either a universal authorization guarantee.

## Technical Context And Constitution Check

Reuse owned helper processes, generation locks and atomic private publication.
The SDK worker needs finite typed errors before fallback is safe. Its session
UID and saved public certificate identity can scope cache reuse without tokens.

The new namespace-only `inet mole_validation` nftables guard runs before legacy
ACCEPT rules; it does not replace the host firewall or flush other tables.
Actual cgroup matching, timed permits, delegation and packet behavior need an
isolated acceptance test; installed tools alone do not prove support. Record
deployment-specific observations only in the private rollout companion.

Constitution checks pass at design level: opt-in/fail-closed policy, truthful
component evidence, failing regressions first, preserved compatibility, bounded
helpers, secret-free generic records and independent review before rollout.
No runtime acceptance is claimed by this check.

## Phase 0: Research And Decisions

The selected approach extends Mole; alternatives and source evidence are in
[research.md](research.md). The canonical fields and limits are in
[data-model.md](data-model.md); contracts define commands/status.

1. Keep every eligible physical endpoint, order approved names first and physical
   identities stably, and deduplicate destinations. No speed benchmarking.
2. Publish only fully validated normalized discovery. A valid global catalogue
   withdrawing approved choices replaces them even if the eligible pool is empty.
3. Scope persistence to provider origin, SDK session UID, configured account
   identifier digest/tier and certificate public identity. Store verified
   entitlement separately within that scope, with its original age; tokens are
   excluded. Missing scope or entitlement disables fallback.
4. Keep hosting-network policy external: the guard supplies observed exit evidence
   to a root-owned validator; that validator cannot open the gate or choose peers.
5. Gate every shared workload, not one UID. Probes alone get a private per-attempt
   cgroup. Keep IPv6 verified-denied, rather than adding IPv6 VPN support.

## Phase 1: Design And Interfaces

### Discovery and preparation

New `mole_pkg/discovery.py`:

- `normalize_candidates(logicals: list, approved_names: list, tier: int,
  require_p2p: bool) -> list` implements Candidate in data-model.md.
- `DiscoveryCache(path: Path).load(scope: str, now_wall: float,
  now_mono: float, boot_id: str, max_age: int) -> Optional[dict]`.
- `DiscoveryCache.publish(record: dict) -> None` validates before atomic fsynced
  replacement; reject symlinks and unsafe owner/mode.

SDK worker outcomes become success, transient, credentials_rejected,
compatibility, invalid_response or local_state. Only timeouts, transport errors,
429 and 5xx allow fallback; unknown/credential/client rejection does not.
Invalid publication preserves the old disk record without granting its use.

`ProtonProvider.prepare_recovery() -> bool` in validated mode reuses a locally
loadable scope-matching session and saved certificate with the existing one-hour
expiry margin; it does not force refresh/password authentication on every cycle.
Try live discovery within budget, then eligible cache on transient failure.
Known credential/certificate rejection invalidates fallback. Missing/expired
credentials still require online preparation. Cache never manufactures keys,
extends certificate validity or authenticates a rejected account.

Persist a private scope-bound pending marker BEFORE any control operation whose
reply can reject credentials. Failure to persist it prevents that operation and
blocks fallback. A typed transient result may clear only its own pending marker,
never a prior rejection; a known rejection makes it durably blocked. Crash or
unclassified completion leaves pending as blocked across restart. Only successful
online credential/entitlement/certificate revalidation clears a blocked record.
Use owned transaction IDs so late jobs cannot clear newer rejection evidence.

A fresh record requires a bounded successful `/vpn/v2` entitlement GET alongside
the nonempty raw catalogue. Effective tier is min(configured tier, MaxTier).
On transient entitlement failure use only the prior complete record within its
original age; do not republish old entitlement with a new timestamp. Recheck
cached tier against current configuration and any newer authoritative restriction.

### Enforcement and validation

New `mole_pkg/validation.py` and `validation_worker.py`; gate operations live in
`network.py` and are bounded async methods:

- `quarantine(config, attempt: dict) -> None`: establish and verify CLOSED.
- `prepare_probe(config, attempt: dict, targets: list) -> dict`: create owned
  cgroup and finite destination allowances before the helper creates sockets.
- `authorize(config, attempt: dict, evidence: dict, ttl: float) -> None`: publish
  an expiring permit only after current identity/policy/evidence checks.
- `revoke(config, attempt: dict) -> None`: remove permits, reap owned helpers,
  remove the owned cgroup and leave workloads closed.
- `validate_exit(config, attempt: dict, deadline: float) -> dict`: restricted exit
  observation followed by the bounded external validator decision.

The guard covers OUTPUT, tunnel INPUT and FORWARD before established/interface
acceptance. CLOSED permits only probe-cgroup traffic to explicit public IPv4
HTTPS destinations and identified replies. DNS/proxy/blocklist/torrent processes
receive no exemption. Preserve local veth management; other veth egress is limited
to selected WireGuard UDP endpoint/port/mark, not arbitrary packets to its IP.
IPv6 remains denied. No root/nobody/whole-service-cgroup exception is allowed.

One orchestrator-owned mutation lock covers identity check, kernel transaction,
acknowledgement and peer replacement. Drain/reap cancelled mutation commands before
replacing a peer. Each connection attempt and validation round owns distinct
kernel sets; stale writes cannot update a newer attempt's active predicate.

Every grant requires TWO independent set memberships: the round's deadline fence
AND its grant. prepare_probe creates the fence with a 90-second kernel timeout,
waits for successful acknowledgement, records ack monotonic time, and only then
starts fresh observation/authorization. The grant set starts empty. Accept proof
only if transport and authorization both remain valid THROUGH ack_time + 90.
That conservative upper bound covers the fence's real expiry even if its creation
was delayed. authorize may populate grant but MUST NOT create/refresh the fence.
A grant arriving after proof expiry is therefore ineffective: the older fence is
already gone. No post-hoc revocation or assumed commit speed is needed for this
safety property. Each refresh requires a new round/fence and new bound proof;
old proof cannot authorize a future fence.

Only serialized orchestration switches the active round chain reference after
checking connection identity. Mutations retain a five-second execution/cleanup
budget and post-ack verification, but the fence enforces expiry independently
if a grant arrives late or the controller dies. Schedule new validation rounds
every 30 seconds from their start, not 30 seconds after slow completion, so the
20-second validation budget fits before the previous fence expires.

Workload permission is the intersection of the independent round fence and grant,
with maximum 90-second lifetime; refresh starts every 30 seconds with fresh proof.
The pre-established fence must expire before either evidence deadline. No
traffic-triggered renewal or fence renewal from a grant operation is permitted.
Policy/peer changes close first. Stale generations, failed rule verification,
expired evidence or controller death cannot leave indefinite permission.

Sequence: CLOSED -> PREPARED -> CONNECTING -> PROBING -> AUTHORIZED -> OPEN;
otherwise CLOSED/EXHAUSTED. Do not publish ready or start torrent synchronization
before opening is verified. Enforcement failure aborts the cycle rather than
trying another peer. On a transient check failure, existing permission can last
only until its already-granted deadline; it cannot be extended from stale proof.

Helper constraints: no shared proxy/resolver, shell, redirects or insecure TLS;
host-resolved public destinations retain hostname/SNI. Only the helper joins its
cgroup before socket creation and drops unnecessary privileges. At most two
HTTPS targets, 64 KiB response each, ten-second observation budget; parse fixed
ipify/ifconfig.co JSON adapters. Recheck intended-peer handshake afterward.
Validator uses the remainder of a 20-second total validation budget. See
[validation contract](contracts/validation.md).

A bounded validator describe operation returns its effective policy revision for
the requested Mole config digest. Freeze it into Attempt and require it in the
validation reply. Revision changes reject the attempt and close its permit.
Operator-driven policy reloads close first; out-of-band edits are detected by
the next 30-second check and old permission cannot exceed its current 90-second
kernel deadline. This is not an immediate revocation guarantee for external edits.

### Recovery and local repairs

Add `ApprovedServerPolicy.next_eligible_at(servers: list, now: float) ->
Optional[float]`. Cooldown stays canonical-entry-IP keyed across name/key changes;
evidence binds public key too. Wake at max(backoff deadline, earliest eligibility)
within one monitor interval, without waiting for another failure threshold.
No candidates means explicit bounded discovery retry. Monotonic deadlines are
never reused across boots. Waiting cannot own forwarding/client locks.

Transport proof is DNS-independent plus current intended handshake. Separately
query the configured local resolver. DNS-only failure permits one supervised
DNS restart per five minutes, with a ten-second total stop/kill/reap/start budget;
then requery. The owned DNS worker gets its own process group; kill/reap all its
download descendants on timeout/cancel. Add a repair-only cached-blocklists
startup path in services/dns.py and dns_main.py: load configured lists from
existing valid cache before binding, never silently disable filtering. Missing
required cache means repair unavailable; no fresh downloads delay the repair
budget. After listener readiness, normal bounded background updates may resume.
DoT-disabled/external resolvers are probed but never created/restarted by Mole.
Persistent failure stays degraded, not a blind reconnect loop.
Only attempt DNS repair while authorization and gate permission are current;
resolver failure during quarantine is expected and cannot trigger worker churn.
Forwarding uses existing independent renewals and mapping repair. Client-only
failure retries synchronization without the service-restart fallback. A generic
hook result never becomes tracker registration proof.

Expose compatible additive fields per [status contract](contracts/status.md).
Display retry remaining seconds and derived wall time, not foreign monotonic
deadlines. DNS failure must remain visible even with verified private transport.

## Project Structure

Create: `mole_pkg/discovery.py`, `mole_pkg/validation.py`,
`mole_pkg/validation_worker.py`, targeted discovery/validation/gate/recovery tests,
and opt-in `tests/network/validated_recovery_acceptance.py`.

Modify: `mole_pkg/providers/proton.py`, `mole_pkg/providers/proton_worker.py`,
`mole_pkg/recovery.py`, `mole_pkg/network.py`, `mole_pkg/network_worker.py`,
`mole_pkg/mole.py`, `mole_pkg/config.py`, `mole_pkg/constants.py`, `mole_pkg/utils.py`,
`mole_pkg/services/api_main.py`, `mole_pkg/services/dns.py`,
`mole_pkg/services/dns_main.py`, existing
relevant tests, `README.md` and `config.example`.
No duplicate runtime logic in the legacy entrypoint.

## Private Rollout And Rollback

A companion outside this repository owns actual server/ASN approvals and the
host validator. It uses exact-IP, age-limited routing evidence; qualification
compares it with tracker classification. Never register the seedbox for every
probe. Four to six distinct candidates is a target, not a reason to widen policy.

After design approval: test-first source work -> isolated packet acceptance ->
independent review -> separately approved rollout. See [quickstart](quickstart.md).
If real isolation/enforcement fails, stop; mocks cannot qualify zero-packet claims.

Rollback closes/verifies the guard and brings down the candidate before restoring
reviewed code/config. Never delete the guard under an active unverified tunnel.
Restart Mole only in an approved window; keep qBittorrent running and prove the
prior endpoint, kill switch, forwarding, application access and tracker state.
No full application copy or ZFS snapshot is needed for this code/config change.

## Complexity Tracking

Kernel quarantine/cgroup support is a material addition beyond old hooks and
needs explicit design approval. Hooks run too late and cannot enforce packet
closure or crash expiry. This namespace-only guard is narrower than replacing
the host firewall or changing VPN managers. Runtime prerequisites and the private
validator are rollout gates, not silently assumed capabilities.
