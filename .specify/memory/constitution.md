# Mole Constitution

## Core Principles

### I. Fail-Closed Networking

Torrent traffic MUST stay inside the configured VPN boundary. Recovery MUST NOT
weaken firewall rules, permit direct egress or broaden approved-server policy.
Existing pin behavior stays strict unless failover is explicitly enabled.

### II. Evidence Before Health Claims

A running process or existing interface MUST NOT alone qualify connectivity.
Report tunnel, lease, client synchronization and hook outcomes separately.
Historical state MUST NOT imply a current forwarding lease.

### III. Test-First Repairs

Reproduce each failure before changing source. Each repair MUST have a regression
that fails before and passes afterward. Run the full existing unittest suite;
disclose failures, warnings and untested acceptance boundaries.

### IV. Preserve Users And Compatibility

Preserve qBittorrent data and process continuity where safe, existing PIA behavior,
supported Python 3.8+, and public API compatibility. Prefer the existing standard
library and provider boundaries; justify dependencies and abstractions.

### V. Secret-Safe, Bounded Operations

External operations MUST have bounded waits and cancellation cleanup. Never
record credentials, private keys, session dumps or tracker passkeys in project
artifacts. Tests use synthetic data and isolated state, not live deployments.

## Compatibility And Privacy Constraints

Generic examples only. Deployment hosts, addresses, authorization and logs remain
outside the public project. Both entrypoints MUST share security/recovery policy.
No broad dependency updates, media cleanup or application-database rollback.

## Development Workflow

Use Spec Kit assessment, fix and test stages. Material scope changes require
owner approval. Independent review and reproduction evidence precede deployment.
Passing unit tests do not qualify an unexercised network acceptance check.

## Governance

This initial constitution records the approved recovery design and existing
project conventions. Amendments require reviewed rationale and semantic version
updates. Review repairs against these principles. Separate source review,
merge/release decisions and production rollout authorization.

**Version**: 1.0.0 | **Ratified**: 2026-11-23 | **Last Amended**: 2026-11-23
