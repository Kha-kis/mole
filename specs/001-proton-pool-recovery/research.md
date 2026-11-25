# Research: Validated Proton Pool Recovery

Created 2026-11-24. Source findings and design decisions; implementation is not
started. The owner approved the specification, not the resulting kernel changes.

## Existing source

- `mole_pkg/providers/proton.py:_filter_servers` retains only the first eligible
  physical entry per logical name. `_fetch_servers` depends on a live API reply;
  there is no saved-discovery fallback in that path.
- `mole_pkg/recovery.py:ApprovedServerPolicy` already rotates approved names,
  deduplicates entry IPs and applies physical-IP cooldown. Preserve these safety
  properties rather than replacing them with unrestricted random choice.
- `mole_pkg/mole.py:_recover_candidates` bounds distinct attempts and
  `_defer_recovery` applies backoff. A next retry must reconcile these deadlines
  with candidate eligibility and remain responsive when the pool is exhausted.
- `mole_pkg/services/api_main.py` and runtime readiness already distinguish
  tunnel/forwarding/client/hook evidence. Extend them compatibly; do not duplicate
  them with an unrelated health service or mislabel a hook as tracker acceptance.
- The existing project constitution requires Python 3.8+ compatibility, no
  unapproved endpoint expansion, bounded operations, synthetic tests, both
  entrypoints and independent review before deployment.

## Reference implementation

Reviewed Gluetun commit `eb3c7ec79d9429b9b3e3185eccde7a4806f61179`:

- [Physical discovery](https://github.com/passteque/gluetun/blob/eb3c7ec79d9429b9b3e3185eccde7a4806f61179/internal/provider/protonvpn/updater/servers.go)
  examines all physical entries and records location, capabilities and keys.
- [Pool selection](https://github.com/passteque/gluetun/blob/eb3c7ec79d9429b9b3e3185eccde7a4806f61179/internal/provider/utils/connection.go)
  supports random and ordered modes; the stable connection picker cycles choices.
- [Publication checks](https://github.com/passteque/gluetun/blob/eb3c7ec79d9429b9b3e3185eccde7a4806f61179/internal/updater/providers.go)
  reject empty, undersized or structurally incomplete discovery replacements.
- [Health checks](https://github.com/passteque/gluetun/blob/eb3c7ec79d9429b9b3e3185eccde7a4806f61179/internal/healthcheck/checker.go)
  use bounded actual connectivity probes, not just advertised server availability.

These are patterns to adapt, not evidence that Gluetun selects the fastest
endpoint or enforces a private tracker's hosting-network authorization.

## Approaches

1. **Expand only the configured list:** smallest change, but leaves all-physical
   discovery, unavailable API, cache validation and exhaustion reporting gaps.
2. **Extend Mole's existing provider/recovery boundaries:** selected by the owner;
   preserves native torrent integration and allows focused regression tests.
3. **Replace Mole with Gluetun:** viable separate migration, but requires proving
   namespace/client continuity, forwarding and host-hook integration again.

## Resolved Design Decisions

- Use the bounded normalized schema and 24-hour maximum in data-model.md, scoped
  to current session/account/entitlement/certificate public identity. Distinguish
  transient API failure from rejected credentials. Full cached recovery includes
  preparation so it is not defeated by a mandatory online refresh first.
- Use opt-in namespace-only nftables enforcement and a private per-attempt cgroup,
  not a root/nobody exception or generic post-connect hook. The latter happens
  after client synchronization and cannot prevent early traffic. Expiring kernel
  permission closes after controller death; unsupported primitives block activation.
- Measure actual exit using fixed restricted HTTPS adapters, then use a bounded
  root-owned external authorizer contract. Keep private hosting-network policy
  and tracker classification outside public core. The authorizer's response is
  bound to current process/attempt/exit/policy and cannot substitute metadata.
- DNS-independent transport proof distinguishes DNS-only faults. Rate-limit a
  supervised resolver-worker repair instead of replacing a proven private tunnel.
  No claim of an independently reproduced DNS implementation defect is made.
- Retain 900-second cooldown; compute the later cooldown/backoff deadline and
  wake within one monitor interval without another failure-count delay. Bound
  the overall cycle and divide remaining candidate time fairly.

## New Enforcement Scope And Evidence Limits

Independent source inspection confirms a material addition beyond existing
hooks: ordinary resolver/proxy processes share the VPN path and cannot be exempt
by UID or whole-service cgroup. INPUT/FORWARD and established flows need gating
as well as OUTPUT. The source's broad endpoint exception also needs tightening
in validated mode to WireGuard's exact UDP transport/mark.

The plan proposes nftables and cgroup v2 only for opt-in validated mode; it is
not a host-wide firewall migration. Actual kernel/cgroup matching and timed
permit acceptance remain required, even if tools are installed. Privileged host
root is trusted, not claimed to be contained by this feature.

Independent design review caught a late-commit expiry issue: a relative grant
timeout alone could be installed after proof expired. The revised design creates
a separate kernel deadline fence and waits for its acknowledgement BEFORE fresh
validation. Proof must cover its conservative upper-bound expiry; grant updates
cannot renew that fence. Both predicates are required, with a fresh round ID for
each renewal. Re-review confirmed this resolves the written-design issue without
assuming command timing or eventual userspace revocation. Runtime proof remains
a required isolated packet acceptance case.

Actual exit observation is documented by [ipify](https://www.ipify.org/).
An external host policy can consult
[RIPEstat network-info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info),
which reports routing-origin ASNs and prefixes, not tracker-specific authorization.
Its periodic source data can differ from a tracker's classification; qualification
must address this rather than claiming a current tracker guarantee.

Private incident observations and actual candidate approvals must not be copied
into this public-project specification. Unit-test fixtures use documentation
addresses, synthetic identities and fake authorization only.
