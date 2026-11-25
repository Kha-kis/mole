# Feature Specification: Validated Proton Pool Recovery

**Feature Branch**: `feat/validated-proton-recovery`

**Created**: 2026-11-24

**Status**: Detailed design and isolated implementation approved 2026-11-24;
implemented and tested in isolation. Merge, release and production rollout remain separate.

**Input**: Improve Mole's endpoint discovery, approved fallback pool, bounded
recovery and truthful health reporting; use Spec Kit. Retain the existing VPN
boundary, qBittorrent integration and tracker authorization restrictions.

## User Scenarios & Testing

### User Story 1 - Recover within the approved pool (Priority: P1)

An operator wants a failed endpoint to be replaced by another approved endpoint
without restarting the torrent application or permitting traffic outside the VPN.

**Why this priority**: A running monitor is insufficient when downloads and
seeding remain disconnected.

**Independent Test**: Supply several synthetic endpoints, make the preferred
one unavailable, and observe selection of a working authorized alternative.

**Acceptance Scenarios**:

1. Given a failed preferred endpoint and a usable authorized alternative, when
   failure is confirmed, recovery tries the alternative without waiting for the
   failed endpoint's cooldown to expire.
2. Given every approved endpoint is unavailable, recovery remains blocked,
   reports exhaustion and a next retry time, and resumes attempts without
   manual intervention after a candidate becomes eligible again.
3. Given several server names share a physical endpoint, recovery does not
   count aliases as independent attempts or independent fallback capacity.
4. Given a candidate fails authorization or authorization cannot be established,
   it cannot carry torrent traffic and cannot be reported ready.

### User Story 2 - Recover during discovery failure (Priority: P1)

An operator wants a temporary discovery outage not to erase known usable choices
or require repeatedly signing in to the provider.

**Why this priority**: Recovery must not depend entirely on a currently available
control service while the data connection is down.

**Independent Test**: Fail discovery with valid saved candidates, then repeat
with expired, malformed, account-incompatible and disallowed saved candidates.

**Acceptance Scenarios**:

1. Given discovery fails and saved discovery is valid and within its age limit,
   recovery may reuse it only after applying current authorization and eligibility.
2. Given discovery returns an empty or invalid result, the existing usable saved
   discovery is not overwritten; the degraded discovery state is visible.
3. Given saved discovery is expired, corrupt, from an incompatible account or
   disallowed by the current policy, it is rejected without widening policy.
4. Given credentials or certificate authorization is rejected, saved server data
   does not bypass that rejection or trigger repeated password authentication.

### User Story 3 - Repair the failing component (Priority: P2)

An operator wants a forwarding, name-resolution or torrent-client update failure
to be distinguished from complete loss of transport.

**Why this priority**: Unnecessary reconnects interrupt useful traffic and make
the original fault harder to diagnose.

**Independent Test**: Inject each failure separately while keeping the other
components working; inspect recovery actions and user-visible health.

**Acceptance Scenarios**:

1. Given transport remains verified but forwarding fails, recovery follows the
   existing bounded forwarding-repair path before considering endpoint rotation.
2. Given only client synchronization fails, it retries synchronization rather
   than replacing the verified tunnel.
3. Given name resolution fails but independent transport proof succeeds, health
   identifies the distinction; it must not silently claim full connectivity.
4. Given tracker registration fails, tracker health is reported independently
   and no unbounded reconnect or registration loop is started.

### Edge Cases

- Logical names move to new physical addresses, public keys or hosting networks.
- Multiple physical endpoints belong to one logical name; aliases share an IP.
- A recovered endpoint is cooling down; all candidates are cooling down.
- Discovery succeeds but withdraws or disables a previously saved endpoint.
- Wall-clock jumps, process restarts and simultaneous recovery triggers occur.
- A late cancelled operation attempts to publish health or replace saved data.
- A saved-data write fails or is interrupted; the prior valid copy must survive.
- All eligible provider paths fail together; no availability guarantee is possible.

## Requirements

### Functional Requirements

- **FR-001**: Retain all eligible physical endpoints for the approved logical
  names; enforce disabled status, account entitlement and required capabilities.
- **FR-002**: Deduplicate physical destinations so aliases cannot bypass cooldown
  or consume repeated attempts in a recovery cycle.
- **FR-003**: Keep preferred-first ordering and existing explicit opt-in failover;
  disabled failover and other VPN providers retain their existing behavior.
- **FR-004**: Never select outside the configured approved pool or allow an
  unauthorized or authorization-unknown candidate to carry torrent traffic.
- **FR-005**: Save validated discovery privately and atomically without credentials;
  current successful discovery supersedes old data, including withdrawals.
- **FR-006**: Permit age-limited saved discovery only after an eligible transient
  discovery failure and current policy/account revalidation. Reject expired,
  future-dated, malformed, account-incompatible and incompatible-version data.
- **FR-007**: Do not treat saved server information as valid credentials, a valid
  certificate, successful transport, successful forwarding or tracker authorization.
- **FR-008**: Preserve bounded and cancellable external operations, single-owner
  recovery, generation checks and bounded distinct attempts per cycle.
- **FR-009**: Expose exhaustion and the next retry deadline; automatically retry
  within one monitor interval of eligibility, respecting cooldown and backoff.
- **FR-010**: Use component-specific recovery and report verified transport,
  name resolution, forwarding and torrent-client synchronization independently.
- **FR-011**: Treat tracker registration as a separate host integration with
  bounded retries; do not report a generic successful hook as proof of registration.
- **FR-012**: Preserve the fail-closed boundary, torrent files, application state
  and running torrent process throughout controlled recovery where safe.
- **FR-013**: Keep both entrypoints and existing public status fields compatible;
  any additional recovery fields must reject stale process/generation evidence.
- **FR-014**: Keep public artifacts generic and secret-free; actual endpoint/ASN
  approvals, account information and host evidence remain private.
- **FR-015**: Demonstrate each behavioral change with a failing regression before
  implementation, then run the full existing suite and independent review.
- **FR-016**: Production expansion requires a separately reviewed candidate list,
  controlled recovery acceptance and rollback. Never enable broad country-based
  fallback merely because too few approved endpoints are available.

### Key Entities

- **Candidate**: logical identity, physical destination, protocol identity,
  capabilities, entitlement and approval evidence.
- **Discovery record**: observation time, compatibility/account scope and validated
  candidates; it contains neither credentials nor a readiness claim.
- **Recovery cycle**: bounded attempt ownership, distinct destinations tried,
  individual cooldowns and the next permitted retry.
- **Health evidence**: time-limited component outcomes belonging to the current
  process and connection attempt; tracker evidence remains independently owned.

## Success Criteria

### Measurable Outcomes

- **SC-001**: Every injected single-endpoint failure with an available approved
  alternative reaches that alternative in the same bounded recovery cycle.
- **SC-002**: In every exhaustion test, an eligible endpoint is retried within one
  monitor interval of the later cooldown/backoff deadline, without manual action.
- **SC-003**: All saved-discovery acceptance/rejection cases produce the specified
  result and no invalid replacement destroys the last valid record.
- **SC-004**: Controlled network tests observe zero torrent packets outside the
  VPN or through an authorization-rejected/unknown candidate.
- **SC-005**: Controlled recovery preserves the torrent process identity and files;
  transport, forwarding, client synchronization and tracker outcomes are recorded
  separately, including any acceptance failures.
- **SC-006**: All existing tests plus the new regressions pass; independent review
  has no unresolved high-severity findings before production deployment.

## Assumptions

- The chosen approach extends Mole; replacing it with another VPN manager is
  outside this feature.
- A private rollout aims for four to six distinct tested physical endpoints;
  insufficient eligible capacity is reported, not fabricated or bypassed.
- Existing credentials, provider session handling and tracker registration remain
  authoritative. New credentials or tracker permissions require owner action.
- Runtime authorization enforcement and saved-data age/account binding must be
  concretely defined in the design before implementation; neither may be reduced
  to a country/name assumption or a successful historical check.
- This specification approves no production restart, endpoint expansion, merge
  or release. Written design/plan review precedes implementation and rollout.

## Clarifications

### 2026-11-24 design preparation

- An empty or malformed raw provider catalogue must not overwrite the last valid
  record. A valid nonempty catalogue that withdraws every approved candidate is
  authoritative: recovery must not resurrect those candidates from an older copy.
- The proposed temporary validation boundary covers proxy and resolver traffic
  as well as torrent sockets, because all share the candidate tunnel. Local
  management remains available. This design scope and its backend requirements
  need owner review before implementation; it is not a deployed guarantee.
