# Approved Recovery Policy

Approved November 23, 2026; this is the generic, public-safe counterpart of the
owner-reviewed design. Deployment details and authorization evidence are not
project artifacts.

## Required Outcomes

1. Never allow direct torrent egress outside the VPN. An interface/process alone
   is not connected: require an attempt-specific recent intended-peer handshake
   and public egress forced through the VPN. Either of two configured HTTPS
   targets may prove transport; no public-endpoint ICMP dependency.
2. Add explicit opt-in approved-server failover. A member pin starts the order;
   subsequent recovery walks the approved list. Saved state and manual commands
   cannot bypass it. Disabled mode preserves strict pins/current unpinned selection.
3. Skip duplicate failed physical entry addresses, use a 15-minute cooldown,
   at most three distinct endpoints per cycle, then back off 30 to 300 seconds
   with bounded jitter. If no approved tunnel works, traffic stays blocked.
4. NAT-PMP is asynchronous, capped at 10 seconds per child operation, with owned
   process cleanup on timeout/cancellation. Adopt only matching valid TCP/UDP
   mappings. Short lease lifetimes constrain refresh timing. Expired saved ports
   cannot be reported available.
5. If VPN egress works but forwarding fails, continue private outbound traffic
   in degraded mode. After three bounded mapping failures, allow one coordinated
   same-endpoint recovery, then approved failover if needed. Preserve a verified
   healthy tunnel when forwarding options are exhausted; never bypass the VPN.
6. Serialize renewal triggers and mapping publication. A late operation from an
   old generation cannot overwrite a new tunnel/lease/client binding. Slow client
   synchronization must not block lease renewal or monitoring.
7. Carry the verified Proton 4.19.1 default plus a validated explicit version
   override into both new and loaded sessions. Preserve saved credentials/cookies;
   classify compatibility rejection with bounded retries, not speculative versions.
8. Expose tunnel, forwarding, client and optional-hook health separately. Keep
   legacy API fields with truthful stricter semantics and additive diagnostics.
9. Preserve PIA, Python 3.8+, existing standard-library conventions, both entrypoints,
   fail-closed firewall, DNS bindings and qBittorrent data/process where safe.
10. No automatic tracker authorization changes. Approved logical server names do
    not guarantee permanent provider ASN; deployment validation remains separate.

## Verification And Scope

Test the original failures before fixes, full suite afterward, and independent
review before rollout. Readiness defaults to a 30-second candidate deadline and
180-second recent-handshake ceiling, further tied to the attempt start. Use
monotonic elapsed deadlines internally. Generic artifacts only; no credentials,
private keys, sessions, tracker URLs or deployment host inventory.

Broader changes need documented scope review and material deviations require owner
approval. No new runtime dependency, automatic executable updates, weakened TLS,
mass torrent operations or application database rollback. Controlled live rollout
is a later gate; passing mocks does not mean live network acceptance.
