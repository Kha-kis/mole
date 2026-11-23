# Bug Assessment: Blocking Provider And Lifecycle Operations

- Slug: blocking-provider-operations (agent-generated)
- Created: 2026-11-23
- Verdict: valid
- Severity: high
- Source: recovery audit and owner-approved extension

## Report And Reproduction

Async Proton methods still call the synchronous SDK. A synthetic 150 ms
`api_request` inside `_fetch_servers` delayed a concurrent 10 ms heartbeat to
161 ms. No live provider request was performed. Latency thread-pool joins,
WireGuard/route commands, hooks and service-restart commands have similar blocking
paths. Namespace initialization also needs a bounded fail-closed lifecycle.

## Required Repair

Use owned processes for blocking SDK work, with private input and staged session
updates adopted only after successful generation validation. Preserve the
existing authentication protocol, saved credentials, client identity and TLS
verification. Authentication deadline: 120 seconds; other API jobs: 45 seconds.

Generalize the async command owner for host commands, private input and environment.
Keep the namespace wrapper compatible. Ordinary commands: 10 seconds; WireGuard
and hooks: 30 seconds; initial namespace setup worker: 120 seconds. Deadlines
include launch/input/wait; cancellation kills and reaps before releasing ownership.

Run namespace protections before enabling a new external path. Preserve installed
identity during candidate preparation. A provider request must not prevent
monitoring or old-tunnel lease renewal. Latency probes must also be async/bounded.

No new runtime dependency, service, container, executable self-update, tracker
authorization change or production deployment. PIA compatibility is required;
rewriting its entire provider API is outside this Proton-focused scope.

## Tests And Risks

Tests must use offline fake SDKs and synthetic children. Cover timeout/cancellation,
state-write rejection, serialized jobs, generation changes, secret-safe errors,
fail-closed setup ordering, hooks, latency, client restart supervision and both
entrypoints. Staging files must be private and cleaned only after owned work ends.
Passing these tests does not establish live Proton, DNS, forwarding or tracker
acceptance. Independent extension review and separate rollout gates remain.
