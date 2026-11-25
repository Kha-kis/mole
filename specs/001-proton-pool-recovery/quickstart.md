# Validation And Rollout Guide

This guide covers the implemented, unreleased feature. Passing source or
synthetic tests is not provider/deployment acceptance. Never run packet tests
in the production namespace.

## Prepare

1. Obtain owner approval of plan.md and its kernel gate/cgroup requirements.
2. Check disposable storage using the deployment's private QA storage preflight; create a
   unique run directory with owner, purpose, creation/review dates and durable
   evidence location. Follow that deployment's approved disposable-data location.
3. Use an isolated Git worktree at that approved location. Preserve the current
   untracked specification documents and copy them explicitly; never reset main.
4. Use a dedicated temporary directory under the QA run for TMPDIR and disable
   Python bytecode creation. Do not install/update dependencies globally.

## Source Validation

From the feature worktree, after each failing regression and repair:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -v
git diff --check
```

Record exact test counts, warnings and failures rather than copying an older
test-count claim. Use targeted `unittest discover -s tests -p 'test_discovery.py' -v`
and analogous validation/recovery patterns during the red/green cycle. Passing
source tests alone cannot qualify kernel enforcement or provider availability.

## Isolated Kernel Acceptance

The implementation adds an explicitly opt-in runner, not part of default tests:

```bash
sudo env PYTHONDONTWRITEBYTECODE=1 TMPDIR="$QA_RUN/tmp" \
  python3 -B tests/network/validated_recovery_acceptance.py \
  --run-dir "$QA_RUN" --synthetic-only
```

The runner rejects an absent lifecycle receipt and never uses reserved live
namespace/interface names. Before creating interfaces or any networks, compare
all host/VPN routes and Docker subnets for overlap. Use unique task-owned names
and isolated documentation-address fixtures; no household address space, Docker
network creation, real credentials or live service mutation is needed.

The runner directly exercises the low-level gate with documentation-address
fixtures and injected test observer/authorizer functions. It does not send those
addresses through the production global-address normalizer. Production entrypoints
always use strict normalization and fixed adapters; no config/env/CLI switch may
enable test injection. Local TLS adapter tests may supply a test CA/context only
through test-only Python construction. Label these separately: packet gating is
real kernel evidence; exit/provider authorization is synthetic until separately
approved provider acceptance. Add tests that production configuration cannot
activate the fixture seam.

Acceptance cases: closed gate blocks torrent-like TCP/UDP, existing root/nobody
sockets, DNS/proxy and forwarded traffic; probes alone work; IPv6 remains denied;
an approved permit opens traffic; denial/expiry/controller death closes it;
stale generation/policy/cgroup reuse cannot reopen it; partial install/revoke
failure fails closed. Verify counters and captures with identifiable fixture
packets and expected positive controls, not a blank capture alone. Check the
existing iptables and wg-quick table interaction as well as the new guard.

Each runner exit cleans up only its owned namespaces, cgroups/interfaces and
table. A private per-invocation resource receipt supports interrupted-run review.
`--quick` is explicitly partial and cannot qualify full expiry acceptance. The
full run also exercises the real observer with local TLS: valid SNI, bad trust/
hostname, redirects, conflicting replies, body limit and cancellation after
cgroup admission. Test injection exists only through Python construction;
production entrypoints reject fixture flags. Retain evidence privately; no global
prune or snapshots.

## Private Candidate Qualification

- Use a separately reviewed host plan for the external validator and an explicit
  ordered list targeting four to six distinct endpoints. Fewer viable candidates
  is a reported limit, not permission to use arbitrary country matches.
- Never validate in a second tunnel using the live client key concurrently;
  use a coordinated exclusive test or separately approved credentials to avoid
  disturbing production/provider roaming.
- Compare observed exit, routing evidence and tracker classification; unexplained
  disagreement blocks that candidate. Tracker registration has its own cooldown.
- Establish code/config rollback, cgroup delegation and backend acceptance before
  enabling validated mode. Preserve secrets privately; no full app copy needed.

## Production Gate

Require independent source/security review, passing regressions and isolated
packet acceptance, an owner-approved candidate list and a maintenance window.
Capture current qBittorrent PID and settings, package/config hashes, namespace
identity, forwarding and tracker state. Start with the existing approved pool;
expand only after qualification. One controlled failure/recovery must demonstrate
current status, working DNS, reachable forwarded port, real transfers, dependent
Arr/Shelfmark access and separate tracker acceptance. Preserve qBittorrent PID
and all files. Monitor at least ten consecutive lease renewals after recovery.

Rollback: verify CLOSED, disconnect candidate, restore reviewed code/config,
then start the prior approved deployment. Do not remove the guard until no
unverified tunnel can carry workloads. Prove previous-path behavior before
retiring task-owned enforcement state. Record any unresolved acceptance gap.
