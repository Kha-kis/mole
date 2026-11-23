# Bounded Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans for the owner-selected native execution. Steps use checkboxes.

**Goal:** Keep monitoring and lease maintenance responsive while external control
operations are slow, and prevent cancelled work from changing live state later.

**Architecture:** Reuse the owned async process-group boundary. Proton's existing
SDK runs in short-lived helpers with private pipes and staged session files;
the parent alone adopts completed state. Network/setup/hook operations use owned
async commands with explicit budgets, preserving installed-connection identity.

**Tech Stack:** Python 3.8+ standard library, asyncio, subprocess, JSON and unittest.
No new runtime dependency or production service.

**Spec:** `.specify/bugs/blocking-provider-operations/assessment.md`, extending
`.specify/bugs/recovery-policy.md`. Detailed design and native method approved.
The original source phase is checkpointed at `089d14c` with 462 passing tests.

## Global Constraints

- No deployment, merge, push, release, live provider calls or tracker changes.
- Existing fail-closed policies, saved credentials and cookie data survive.
- SDK authentication: 120 seconds; other SDK API jobs: 45 seconds.
- Ordinary commands: 10 seconds; WireGuard and hooks: 30 seconds; initial
  namespace setup worker: 120 seconds. Child ownership covers launch, input and wait.
- Timeout/cancellation kills the owned group, reaps the child, rejects adoption
  and cleans only the completed job's private staging directory.
- New disposable test payloads use the operator's approved QA location/TMPDIR.
- Generic public artifacts only. Secrets never enter arguments, logs or reports.
- PIA behavior remains covered; a full PIA API rewrite is not included.

## Review Focus

- Cancellation arrives during spawn or stdin backpressure: no orphan child or
  session adoption after cancellation (Task 1/2).
- Saved session changes while a job is queued or its generation changes: do not
  overwrite newer state or allow two SDK writers (Task 2).
- A healthy installed tunnel exists while a candidate is being prepared: keep
  its lease/health identity valid until the actual controlled switch (Task 3).
- Setup times out partway through namespace creation: DROP precedes a usable
  external path; no plaintext fallback (Task 3).
- A helper/hook prints credentials or malformed output: fixed diagnostics only,
  no credential-bearing output copied to logs (Tasks 2/3).

## Task 1: General Owned Command Runner

**Files:** `mole_pkg/utils.py`, new `tests/test_owned_commands.py`, existing
`tests/test_async_commands.py`.

**Interfaces:** `async_run_command(cmd: list, timeout: float, env=None,
input_data=None) -> subprocess.CompletedProcess`; input is optional bytes.
`async_run_in_netns(cmd, netns, timeout, env=None)` delegates with the existing
namespace prefix. Nonzero returns normally; timeout/cancellation reaps and raises.

- [x] Write failure-first tests for host-child heartbeat, private stdin/env,
  timeout during blocked input, repeated cancellation and cancellation during
  spawn. Assert actual child cleanup and bounded elapsed time.
- [x] Run targeted tests; expected failure: missing generic interface.
- [x] Refactor the existing owner without weakening its namespace tests. Include
  launch/input time in the same deadline and safely drain creation before kill.
- [x] Run `python3 -m unittest discover -s tests -v`; expected: all pass with
  disclosed baseline warnings. Commit with verified GitHub noreply identity.

## Task 2: Isolated Proton SDK Jobs

**Files:** `mole_pkg/providers/proton.py`, new
`mole_pkg/providers/proton_worker.py`, new `tests/test_proton_worker.py`,
new offline fake SDK fixtures under `tests/fixtures/fake_proton/`, existing
`tests/test_proton_client_identity.py`.

**Interfaces:** `ProtonProvider._run_sdk_job(operation, endpoint='', method='GET',
data=None) -> dict` owns one serialized staged session transaction. Allowed
operations are authenticate and the three existing API endpoints only.
`_api_request` is async. Public authenticate/fetch/register signatures stay async.
Key conversion stays the existing algorithm, but API key retrieval is awaited.

- [x] Add failure-first real-helper/fake-SDK tests: heartbeat during a delayed
  request, stuck timeout, cancellation after a staged write, generation change,
  serialization, saved-session preservation and secret-safe output/errors.
- [x] Run targeted tests; expected: current SDK path blocks or interfaces absent.
- [x] Implement a private per-job directory under provider state, copying only
  the saved session. Worker credentials use stdin, not argv/environment. Adopt
  session by atomic replace only on successful current-generation completion.
  Kill/reap before retiring the job directory; never let a worker write live state.
- [x] Restrict operation/method/endpoint dispatch and return fixed error classes.
  Adapt old injected-SDK tests to the new boundary, preserving all assertions.
- [x] Replace synchronous latency joins in async server selection with bounded
  async ping commands (three seconds each, concurrency at most ten); preserve
  existing load fallback and configured latency behavior.
- [x] Run the full unittest suite; expected: all pass. Write fix evidence and
  commit only intentional files with the verified noreply identity.

## Task 3: Bounded Setup, Switching And Hooks

**Files:** `mole_pkg/network.py`, `mole_pkg/mole.py`, new
`mole_pkg/network_worker.py`, new `tests/test_bounded_lifecycle.py`, relevant
existing network/readiness/cleanup fixtures.

**Interfaces:** async namespace initialization (120 seconds), async endpoint
reconciliation (10 seconds per command), async disconnect (30 seconds), async
`Mole._run_hook(...) -> bool` (30 seconds). Existing synchronous network helpers
remain for legacy callers; runtime uses the bounded variants.

- [x] Write failure-first tests for slow setup/hooks/service commands without
  heartbeat stalls, deadline/cancellation cleanup and secret-safe hook logs.
- [x] Add fail-closed ordering tests: DROP before bringing up external veth/NAT;
  a failed policy command aborts before enabling that path. No real networking.
- [x] Add preparation tests: candidate SDK/certificate work cannot relabel or
  suppress healthy installed tunnel checks/lease maintenance. Invalidate and
  advance generation at the actual switch, rejecting old mapping/client results.
- [x] Implement bounded namespace/setup helpers and async hooks/disconnect/client
  restart. Check endpoint-rule reconciliation before success. Preserve existing
  rules, DNS, routes and service ownership; no direct fallback.
- [x] Update only fixtures whose old sync mocks no longer match the boundary;
  retain assertions and forbid accidental live namespace/provider calls.
- [x] Run full unittest, firewall and PIA regressions; expected: all pass. Commit.

## Task 4: Verification And Independent Extension Review

**Files:** the new bug's `fix.md`/`test.md`, generic README/CHANGELOG updates;
private operator evidence stays outside the repository.

- [x] Re-run the original 161 ms SDK heartbeat reproduction using the repaired
  path and offline SDK. Run real-child, worker, lifecycle and complete suites.
- [x] Run both entrypoint smoke checks and Python 3.8 syntax checks. Disclose
  actual-interpreter/live-network checks not exercised and all remaining warnings.
- [x] Obtain one fresh independent review of the extension from `089d14c` onward.
  Fix important findings through failure-first regressions and a green full suite.
- [x] Read-only Spec Kit verification records partial if live acceptance remains
  unperformed. Reconcile earlier phase reports by dated addenda, not erasure.
- [x] Preserve source/evidence/lifecycle metadata; no implicit QA cleanup, live
  installation, public push or release. Hand off the separate rollout gate.

## Self-Review And Execution

All approved extension contracts map to Tasks 1-4. The shared command runner
precedes both worker boundaries. Staged session adoption and installed-identity
preservation are distinct; neither may be replaced by fire-and-forget threads.
Native execution remains selected. Written-plan confirmation precedes code edits.
