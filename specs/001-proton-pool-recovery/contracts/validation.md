# Candidate Validation Contract

## Configuration

- `PROTON_RECOVERY_MODE`: legacy (default) or validated.
- `PROTON_DISCOVERY_MAX_AGE`: integer 0..86400, default 86400; only validated
  mode uses fallback, and zero disables it.
- `PROTON_EXIT_VALIDATOR`: absolute executable path, mandatory in validated mode.
- `PROTON_VALIDATION_CGROUP_ROOT`: absolute cgroup-v2 directory delegated to the
  Mole service, mandatory in validated mode; never the whole-service exemption.
- `PROTON_RECOVERY_CYCLE_TIMEOUT`: integer 120..600, default 300 seconds.

Validator file and parent components must be root-owned and not group/world
writable; file must be regular, executable, not a symlink. No shell expansion.
Keep all existing approved-list, cooldown and attempt settings/validation.
Validated mode fails activation if Proton/failover/validator/enforcement is absent.
No implicit package installation, user/group change or service delegation change.

## Probe Isolation

The parent creates a private attempt cgroup under the delegated root, starts a
waiting helper with no network sockets, moves it into that cgroup, verifies
membership, installs finite probe allowances and only then releases the helper.
The helper cannot delegate a general proxy or spawn uncontrolled descendants.
Workload UID, including root/nobody, is not a probe identity. Cgroup handles must
not be reused while stale rules/evidence reference them. Remove allowances before
removing the group. Parent cancellation kills/reaps owned descendants first.

Only fixed HTTPS adapters for `api.ipify.org` and `ifconfig.co` are supported.
Use resolved public IPv4 addresses, bind to the VPN device, preserve SNI and
verify the certificate. Do not trust environment proxy settings or follow a
redirect. No shared namespace DNS while quarantined. Host bootstrap lookup is
bounded and rejects private/reserved results; its failure is explicit, not a
reason to permit workload DNS. Retry both targets within one ten-second budget.
Reply body maximum 64 KiB/target. Responses must agree if both succeed; a
contradiction is rejected, not resolved by taking the first result.

The helper's response is tied to the current Attempt and a fresh intended-peer
handshake. It supplies only observed public exit and transport evidence, never
an authorization decision based on discovery metadata.

## External Authorizer

Executed on the host, outside the candidate namespace, as one owned child group.
Request/response via stdin/stdout JSON; never arguments/env containing secrets.
Maximum request/reply 64 KiB; no raw stdout/stderr is logged. The total helper
plus authorizer budget is 20 seconds; timeout/nonzero exit/cancel/malformed reply
is authorization_unknown. No hooks or password authentication are invoked here.

Request contains Attempt, ValidationRound identity and freshly observed exit IP.
Both describe and validate include `config_digest`, the same canonical public
configuration digest. This allows validation to recompute the effective policy
revision rather than trusting a previously described revision alone.
Response echoes those identities, exit IP and policy revision, with allowed/asns/observation/expiry/
reason matching ExitEvidence in data-model.md. Every identity must match exactly.
Missing fields, type coercions, stale/future proof, extra peer/policy identity or
an expiry beyond 120 seconds is rejected. A denial is not retried as approval.
Before freezing Attempt, a describe operation supplies the effective Mole config
digest and requests the validator's current policy revision, returned as 64 hex
characters. Describe and validation share the 20-second total budget, including
bootstrap observation. Validation must echo the described revision exactly.
The root-owned validator is trusted policy code: it MUST NOT modify firewall
state or request another server. This is a contract, not containment of host root.

Mole requires a new observation on each validation/permit-refresh cycle. An
authorizer may reuse its own supporting exact-IP routing record only under a
separately documented private age/policy limit; it cannot reuse a prior exit-IP
observation as if it came from the current candidate.

## Kernel Enforcement

Own only `inet mole_validation` in the VPN namespace; use atomic transactions.
Base-chain priority precedes legacy filter ACCEPT/established handling. CLOSED
must apply before any peer replacement, including startup with an old namespace.
Cover OUTPUT, tunnel INPUT and FORWARD; preserve only explicit management,
WireGuard outer transport, probe traffic and their strictly identified responses.
IPv6 remains denied with checked rules. No global flush or unrelated table edit.
Management is limited to the exact host address and host-initiated connections:
INPUT original direction and OUTPUT reply direction. Neither new nor established
namespace-initiated connections to a host proxy or DNS service are exempt.

OPEN requires two independent kernel predicates, the validation round's deadline
fence AND its grant. prepare_probe creates the 90-second fence, receives commit
acknowledgement and only then begins fresh observation/authorization. Proof must
cover acknowledgement_time + 90 seconds; this is a conservative upper bound on
the already-running fence's expiry. authorize can add a grant but cannot create
or refresh its fence. A late grant is ineffective after fence expiry, even if
its controller dies. A state file cannot open traffic.

Each refresh uses a new ValidationRound ID, fence and fresh bound proof; old
proof cannot authorize a new fence. Every grant/active-reference update checks
installed peer, process, generation, policy and current provider authorization.
Pending refresh rounds leave readiness tied to the still-valid active round.
Changed eligibility or durable rejection closes and drains existing permission
before publishing the change. A new candidate closes immediately.

Serialize all gate mutations and peer replacement under one owner/lock, including
the asynchronous kernel commit. Cancel/drain old commands before replacement.
Attempt/round-specific sets prevent stale writes from modifying newer predicates;
only serialized orchestration changes the active reference. Budget five seconds
for mutation/cleanup and verify after acknowledgement. Over-budget mutations are
enforcement failures, but expiry safety does not depend on that budget or eventual
revocation: the independent earlier fence must already make a late grant useless.

On normal shutdown/cancel, revoke before disconnect. If revocation cannot be
verified, attempt bounded interface-down and abort further recovery. Leave guard
rules installed. Never delete the table while a candidate interface can carry
workloads; a degraded cleanup is an explicit operational failure.

Threat model: trusted host administration and service supervisor. A privileged
workload capable of rewriting netfilter or escaping cgroups is outside this
boundary; this feature does not claim isolation from hostile host root.

## Failure Diagnostics and Resolver Freshness

Validation failure logs identify only a fixed implementation stage and outcome.
Never interpolate exception messages, helper output, requests or account data.
Classifying a failure must not change denial, cancellation, revocation, timeout
or disconnect semantics. The aggregate readiness error remains compatible.

DNS health queries the configured resolver with a fresh 128-bit random label
under example.com, not a fixed cacheable name or a direct public resolver.
Validate transaction, question, flags and complete bounded record framing.
Accept a positive IPv4 answer or a well-formed SOA-backed negative response;
empty local filtering responses, SERVFAIL, mismatched and truncated replies are
not health evidence. Ordinary caching and filtering remain unchanged. This
checks resolver/upstream behavior, not tracker registration or provider uptime.
