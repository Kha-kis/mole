# Health Probe Lease Starvation

## Assessment

A single failed HTTPS transport probe clears `state.connected`. The forwarding
loop used that same flag to decide whether to renew a short NAT-PMP lease.
Consequently a transient probe failure could cause a real forwarding outage
before the next successful watchdog check, even when the private tunnel stayed
installed. Source tracing and a failing real-loop/provider regression confirm
the coupling. This is not evidence that every NAT-PMP timeout has the same cause.

## Fix Contract

- Continue bounded forwarding maintenance for the current installed Proton
  peer, identified by nonempty peer/address and matching runtime generation.
- Skip maintenance during WireGuard replacement or for missing/stale identity.
- Preserve failed transport evidence and its error. A successful mapping alone
  cannot mark transport or torrent-client readiness true or initiate client sync.
- Preserve PIA's connected-state gating, network policy, DNS, provider request
  budgets and approved-endpoint policy. No extra dependency or tracker operation.

## Test Record

Before implementation, the failed-probe regression failed because no UDP/TCP
mapping requests were made. Guard cases also detected maintenance against absent
or stale installed identity. The missing-address case failed separately before
its guard was added. Real keepalive and Proton mapping code run against synthetic
subprocess replies, using private temporary state rather than a live tunnel.

Existing short-lease/health fixtures now include the installed address and peer
that real runtime setup establishes; their original behavioral assertions remain.
Full-suite and independent-review results belong in the change/rollout receipt.
Live deployment is a separate gate; no synthetic result proves MaM acceptance.

Independent review found a failed-then-successful mapping sequence could replace
the original transport diagnostic with a stale forwarding error. A regression
failed with that exact error mismatch before correction. Mapping failures now
preserve an existing transport error while disconnected. Explicit PIA connected/
disconnected loop checks and a configured torrent-client regression also run.
