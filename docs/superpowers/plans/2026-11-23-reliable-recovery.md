# Reliable VPN Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task. Steps use checkboxes.

**Goal:** Correct false readiness and ineffective, blocking recovery without
weakening the VPN boundary or changing torrent data.

**Architecture:** Retain the provider/orchestrator/client split. Add a narrow
async command helper and a pure approved-server policy; coordinate runtime
operations through generation-aware locks. Spec Kit bug records carry assessment,
fix and independent verification for each repair.

**Tech Stack:** Python 3.8+, asyncio, subprocess, dataclasses and unittest;
WireGuard/NAT-PMP commands already required by the project. No new runtime package.

**Spec:** `.specify/bugs/recovery-policy.md` and the four sibling assessment files.

## Global Constraints

- Preserve fail-closed networking, PIA, both entrypoints and existing API fields.
- Approved failover is opt-in; no unapproved or direct-egress escape path.
- Readiness 30 seconds/candidate, handshake age at most 180 seconds and new to
  the attempt; NAT-PMP child limit 10 seconds; cooldown 900 seconds; at most
  three distinct endpoints/cycle; exhaustion backoff 30 to 300 seconds.
- Healthy tunnel plus failed forwarding is degraded; no working tunnel is blocked.
- Version default 4.19.1; explicit validated override, never guessed updates.
- Test-first; generic public records; no real credentials or production state.
- No deployment, release, merge or source-history rewrite as a side effect.

## Review Focus

- A logical server changes physical address or shares another failed address:
  test fresh resolution and physical cooldown in Task 4.
- Both control triggers arrive during slow mapping/client work: test single
  renewal, generation rejection and cancellation in Tasks 2 and 4.
- Clock changes, truncated state and process restart: reject false readiness or
  expired saved leases in Tasks 2 and 3.
- Public probe returns HTTP denial despite valid TLS, or an endpoint ignores
  ICMP: transport proof must not be confused with content authorization (Task 3).
- Permanent provider rejection differs from transient outage: bound retries and
  preserve session data; report truthful verification boundaries (Tasks 1 and 5).

## Setup And Baseline

- [x] Isolated branch/workspace; no production package edits.
- [x] Official Specify CLI 1.4.4 pinned to its release, Codex skills and bundled
      Bug Triage Workflow 1.0.2. Generated files reviewed; no existing source edits.
- [x] Project constitution and four assessments, hooks checked (none registered).
- [x] Non-mutating reproductions for readiness, event-loop blocking and pin reuse.
- [x] Baseline: `python3 -m unittest discover -s tests -v`, 399 pass. Existing
      warnings: three unclosed test configuration files in `test_providers.py`
      and an unawaited `main_async` warning attributed during DNS tests. Do not
      claim warning-free baseline or silently hide them.
- [x] Owner approved the plan and native execution before code edits.

## Task 1: Client Compatibility And Configuration

**Files:** `mole_pkg/config.py`, `mole_pkg/providers/proton.py`,
`tests/test_config.py`, `tests/test_proton_client_identity.py`, `config.example`.

**Interfaces:** `Config.proton_client_version -> str` defaults to `4.19.1`;
`ProtonSessionWrapper(session_file, client_version='4.19.1')` constructs fixed
`linux-vpn@<version>`/`ProtonVPN/<version> (Linux)` identities. `load()` applies
the same identity without modifying credential/cookie fields. Constructor must
remain compatible with existing one-argument callers.

- [x] Write `test_default_identity_is_verified_version`, `test_override_applies_to_new_and_loaded_session`,
      `test_invalid_identity_rejected` (newline/prefix/URL/empty explicit value),
      `test_rejection_does_not_loop_password_authentication` and secret-log tests.
- [x] Run targeted tests against the baseline and record expected failures.
- [x] Implement validation and bounded rejection classification. Retain existing
      session decode/refresh fixes; do not bypass TLS verification.
- [x] Run targeted suite plus config/provider regressions; write the slug's
      `fix.md` including touched files and any deviations.
- [x] Verify Git author/committer use the owner's verified GitHub noreply identity
      before committing only the reviewed files; never inherit a personal email.

## Task 2: Bounded Asynchronous Mapping

**Files:** `mole_pkg/utils.py`, `mole_pkg/providers/proton.py`, `mole_pkg/mole.py`,
`tests/test_utils.py`, `tests/test_port_forward_renewal.py`.

**Interfaces:** `async_run_in_netns(cmd: list, netns: str, timeout: float) ->
subprocess.CompletedProcess` uses owned async child execution. Nonzero exit is
returned for caller classification; timeout raises `asyncio.TimeoutError` after
kill/reap; cancellation reaps then propagates. Keep existing sync helpers intact.
`ProtonProvider._request_port_mapping(protocol)` and `_renew_port_mappings()`
become async; public setup/refresh keep their existing async boolean interface.
Internal mapping writes carry the orchestrator's current integer generation.

- [x] Add real short synthetic child tests: `test_mapping_wait_keeps_heartbeat_running`,
      `test_command_timeout_reaps_group`, `test_command_cancellation_reaps_group`.
      Assert completed ownership cleanup, not just that a mock received cancel.
- [x] Add `test_old_generation_cannot_publish_mapping`, matching TCP/UDP,
      timeout/partial reply, short/expired lease and clock-jump cases.
- [x] Observe failures, then implement async child handling and a single mapping
      writer. Do not publish state until both replies and generation are valid.
- [x] Calculate refresh delay from remaining monotonic lifetime, bounded by the
      existing 45-second schedule; expired lease cannot remain forwarding-ready.
- [x] Run full mapping/client-lock regressions, record `blocking-port-mapping/fix.md`,
      and commit the reviewed change with the verified noreply identity.

## Task 3: Readiness And Truthful Status

**Files:** `mole_pkg/mole.py`, `mole_pkg/utils.py`, `mole_pkg/config.py`,
`mole_pkg/services/api_main.py`, `tests/test_mole.py`, `tests/test_api_main.py`,
new `tests/test_recovery.py`, `config.example`.

**Interfaces:** `Mole._wait_for_readiness(peer_key: str, attempt_started: float)
-> bool` shares a monotonic 30-second budget with child probes. A helper parses
`wg show mole latest-handshakes` for exactly the intended peer. `VPNState` adds
`generation`, `tunnel_ready`, `forwarding_ready`, `client_ready`, `last_error`;
existing `connected` mirrors verified tunnel readiness. Atomic runtime evidence
contains generation and validity timestamps, not secrets; API must reject old,
truncated, mismatched or restart-stale evidence.
`read_wg_peer_key(config_path: str) -> str` reads only the intended peer's public
key using the standard INI parser, rejects ambiguous/multiple peers, and never
logs the config (which also contains private material). This works for either
provider without relying on Proton-specific private selection attributes.

Configuration: `VPN_READY_TIMEOUT=30`, `VPN_READY_PROBES` is a comma-separated
pair of public HTTPS URLs, without credentials/query/fragment. Proposed defaults
are `https://www.cloudflare.com/` and `https://www.wikipedia.org/`. Use existing
curl inside the namespace with `--interface mole --noproxy '*' --proto '=https'`,
no redirects, at most five seconds/probe bounded by remaining attempt budget.
Any verified TLS/HTTP response proves transport, including HTTP denial; do not
use `--fail` to turn content authorization into a tunnel outage. Never use the
public WireGuard endpoint address as the egress target.

- [x] Add failure-first tests for missing/zero/stale/future/foreign handshake,
      empty/failed command, old attempt, one/all failed targets, ignored endpoint
      ICMP, HTTP denial, probe deadline/cancellation and interface enforcement.
- [x] Add atomic-status tests for restart/truncation/generation/expired lease;
      retain legacy fields and add separate readiness fields/metric samples.
- [x] Implement readiness invalidation before reconnect and success only after
      handshake/egress proof. Remove endpoint-ping dependence from healthy state.
- [x] Run readiness/API/firewall regressions, record `verified-readiness/fix.md`
      and commit only reviewed files with verified noreply identity.

## Task 4: Approved-List Recovery And Degraded Mode

**Files:** new `mole_pkg/recovery.py`, `mole_pkg/config.py`,
`mole_pkg/providers/proton.py`, `mole_pkg/mole.py`,
`tests/test_config.py`, `tests/test_providers.py`, `tests/test_recovery.py`,
`config.example`, `README.md`.

**Interfaces:** `ApprovedServerPolicy(names: list, initial: str = '', cooldown:
float = 900)` owns ordering and cooldown, independent of network commands.
`candidates(servers: list, now: float) -> list`, `failed(entry_ip: str, now: float)
-> None`, and `succeeded(entry_ip: str) -> None` use resolved eligible dictionaries
from the existing provider. `ProtonProvider.record_server_failure(reason: str)
-> None` records the selected physical endpoint. Default provider behavior for
other VPNs is unchanged.

Configuration: `PROTON_FAILOVER_ENABLED=false`, `PROTON_FAILOVER_SERVERS=`
(ordered names), `PROTON_FAILOVER_COOLDOWN=900`, `PROTON_FAILOVER_MAX_ATTEMPTS=3`.
Enabled mode requires a nonempty valid list; an existing pin must belong to it.
Pin begins the order, then wrap within the list. Saved/manual controls cannot
escape it. Disabled mode retains existing pinned/unpinned selection.

- [x] Write policy tests for ordering, enabled validation, disabled compatibility,
      first failed/second healthy, outside pin, all unavailable, new physical IP,
      duplicate failed physical IP, cooldown expiry and saved/manual bypass.
- [x] Write orchestration tests for overlapping watchdog/manual/scheduled triggers,
      cancellation, stale writes and exhaustion backoff. Require one renewal owner.
- [x] Write mapping-degraded tests: three failed attempts, one same-endpoint
      recovery, approved failover only, valid lease clears budget; reconnect alone
      does not. Preserve a verified healthy tunnel after mapping exhaustion.
      If an unsuccessful later candidate tore it down, allow one bounded restore
      of the previously verified approved endpoint, within the same distinct-endpoint
      cap. Failed restoration is blocked, not falsely reported degraded/healthy.
- [x] Implement the pure policy and generation-aware serialized recovery using
      earlier task interfaces. Do not auto-edit tracker/ASN authorization.
- [x] Audit other synchronous provider SDK/latency calls encountered on this
      path. Record residual blocking or proposed material scope changes explicitly;
      do not assert all provider calls are nonblocking from NAT-PMP tests alone.
- [x] Run policy/orchestration regressions, write `failed-pin-recovery/fix.md`
      and commit reviewed files with verified noreply identity.

## Task 5: Independent Verification And Handoff

**Files:** four `.specify/bugs/*/test.md` reports, `README.md`, `CHANGELOG.md`,
generic test fixtures as needed. No deployment configuration belongs in this repo.

- [x] Run the actual original reproductions against the repaired code, targeted
      regressions and `python3 -m unittest discover -s tests -v`. Record exact
      exit status/counts and every baseline/new warning. Install no broad dev
      dependencies merely to replace the established suite.
- [x] Run entrypoint/version, Python 3.8 syntax compatibility, firewall and PIA
      checks. Keep generated QA files in the operator's approved disposable area.
- [x] Read-only Spec Kit test stage writes `verified`, `partial` or `failed` per
      slug; skipped real-network acceptance cannot be called live-verified.
- [x] Fresh independent branch review checks source, both entrypoints, policy
      bypasses, process cleanup, races, tests and privacy. Resolve findings through
      fix then test stages; never change source from the verification-only stage.
- [x] Remove constitution's temporary sync-review note before commit; inspect
      all generated `.specify`/`.agents` files for host data and unnecessary runtime
      state. Commit only intentional generic artifacts, no tool cache or fixtures.
- [x] Provide a private rollout checklist with package/config before-images,
      current server/ASN checks, exact reviewed file set, one controlled restart,
      tunnel/DNS/lease/client/MaM acceptance and rollback. Deployment requires a
      separate gate; no auto merge, release or production restart in these tasks.

## Self-Review

All approved contracts map to Tasks 1-5. Interface names above are the shared
implementation contract; any necessary change must update its callers, tests
and plan together. Five review-focus cases map to explicit tests. The plan
defines boundaries, not complete implementation bodies. Known baseline warnings
and unexercised live-network checks remain visible rather than silently waived.

## Execution Choice

Recommended: native execution with one fresh independent whole-branch reviewer.
The tasks overlap in provider/config/orchestrator files and depend closely on
the same generation/lock interfaces; simultaneous writers would add integration
risk. Task-by-task subagent execution is an available, more expensive alternative.
Owner approved native execution before source edits. Merge, release and live
deployment remain separate gates. See verification reports for remaining limits.
