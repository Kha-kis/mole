# Tasks: Validated Proton Pool Recovery

Input: approved spec.md; plan.md, data-model.md and contracts awaiting design
approval. All implementation boxes intentionally remain unchecked.

Every test-first pair requires observing the specific failure on the baseline,
then the targeted pass and relevant regressions after the repair. Do not mark
tasks complete from mocks alone where real packet acceptance is required.

## Phase 1: Setup

- [ ] T001 Establish isolated source/test work under the approved QA lifecycle;
  preserve specs/001-proton-pool-recovery, run the baseline unittest suite, and
  record counts/warnings in the private run evidence. Covers FR-014, FR-015.
- [ ] T002 Add red configuration/helper-error tests in tests/test_config.py and
  tests/test_proton_worker.py: legacy defaults; validated-mode prerequisites;
  cache/cycle bounds; transient versus credential, compatibility, invalid and
  unknown failures. Covers FR-003, FR-006, FR-007, FR-008.
- [ ] T003 Implement validated-mode configuration in mole_pkg/config.py and
  mole_pkg/constants.py, plus finite SDK outcomes in mole_pkg/providers/proton_worker.py and
  mole_pkg/providers/proton.py per contracts/validation.md. Ensure existing callers remain
  compatible and secret-bearing SDK exceptions never escape. Covers FR-003,
  FR-006, FR-007, FR-008, FR-014.

## Phase 2: US1 - Approved Pool And Enforcement (P1)

- [ ] T004 [US1] Add red tests/test_discovery.py cases for multiple physical
  entries, disabled/tier/P2P filtering, invalid IP/key/hostname, duplicate aliases,
  conflicting keys, stable order and withdrawn entries. Covers FR-001, FR-002.
- [ ] T005 [US1] Implement normalize_candidates in mole_pkg/discovery.py and
  validated-mode provider consumption in providers/proton.py. Implement all
  canonical data-model.md fields Candidate.name, Candidate.hostname,
  Candidate.entry_ip, Candidate.exit_ip, Candidate.public_key, Candidate.port,
  Candidate.tier, Candidate.features, Candidate.load and Candidate.country;
  preserve legacy filtering/selection behavior. Covers FR-001, FR-002, FR-003.
- [ ] T006 [US1] Add red tests/test_validation_gate.py for closed-first ordering,
  no UID/service-cgroup bypass, prior connections, both families, narrow outer
  WireGuard traffic, timed permits, stale identity, partial install and revoke
  failures; add data-model.md Attempt validation cases in tests/test_validation.py.
  Include delayed refresh versus replacement, commits beyond proof lifetime and
  stale permit-set updates that must not reference the active chain. Prove the
  two-predicate deadline fence makes a late grant ineffective without revocation.
  Covers FR-004, FR-008, FR-012, SC-004.
- [ ] T007 [US1] Implement owned namespace-only nftables quarantine/probe/permit/
  revoke operations in mole_pkg/network.py and network_worker.py; implement
  data-model.md Attempt.process_identity, Attempt.generation, Attempt.nonce,
  Attempt.candidate, Attempt.policy_revision and Attempt.deadline in validation.py.
  Implement data-model.md ValidationRound.id, ValidationRound.attempt,
  ValidationRound.acknowledged_mono and ValidationRound.fence_max_ttl; grant updates
  cannot create/extend a round fence or reuse old evidence for a new round.
  Reject unsupported enforcement without mutating active legacy behavior.
  Covers FR-004, FR-008, FR-012.
- [ ] T008 [US1] Add red tests/test_validation.py for wrong cgroup, socket created
  too early, stale identity, observed-versus-advertised exit, two-target conflict,
  redirects, private bootstrap answers, oversized responses, rejected/unknown
  authorizer, timeout/cancel/child cleanup and expiry. Include describe/validate
  policy changes during an attempt and while OPEN. Covers FR-004, FR-007, FR-008.
- [ ] T009 [US1] Implement the restricted helper/parent protocol in
  mole_pkg/validation_worker.py and validation.py per contracts/validation.md.
  Implement data-model.md ExitEvidence.attempt, ExitEvidence.exit_ip,
  ExitEvidence.round_id,
  ExitEvidence.allowed, ExitEvidence.asns, ExitEvidence.observed_wall,
  ExitEvidence.expires_wall and ExitEvidence.reason. Keep tracker credentials,
  discovery ExitIP and ordinary hooks out of this proof. Covers FR-004, FR-007,
  FR-008, FR-011, FR-014.
- [ ] T010 [US1] Add red tests/test_validated_recovery.py for close/connect/probe/
  authorize/open ordering, known denied and unknown candidates, replacement and
  shutdown cancellation, gate expiry, late success and controller restart.
  Assert no premature torrent sync or automatic torrent-service restart.
  Covers FR-004, FR-008, FR-012, SC-001, SC-005.
- [ ] T011 [US1] Integrate the validated-mode lifecycle and independent 30-second
  permission refresh in mole_pkg/mole.py; keep legacy/PIA paths unchanged, reject
  stale peer/generation/policy evidence before each permit refresh, and bound
  authorization by contracts/validation.md. Covers FR-003, FR-004, FR-008, FR-012.
- [ ] T012 [US1] Add red tests/test_recovery_policy.py and
  tests/test_recovery_orchestration.py using a fake clock for all-pool cooldown,
  eligible alternatives, alias/key changes, backoff, cycle fairness and waking
  without another failure-count delay. Covers FR-002, FR-008, FR-009, SC-001, SC-002.
- [ ] T013 [US1] Implement next_eligible_at in mole_pkg/recovery.py and deadline
  scheduling in mole_pkg/mole.py; apply finite overall/per-attempt budgets and
  explicit no-candidate versus cooldown reasons. Waiting must not hold mapping
  or client locks. Covers FR-002, FR-008, FR-009.

US1 checkpoint: synthetic candidate failure/recovery passes while unsafe traffic
is denied. Real packet proof remains a mandatory later gate, not implied here.

## Phase 3: US2 - Discovery Outage Recovery (P1)

- [ ] T014 [US2] Add red tests/test_discovery.py for cache scope/size/type/version,
  age/future time/same-boot monotonic age, unsafe ownership/path/symlink, interrupted
  publication, valid withdrawals, rejected refresh and reread-not-refreshing-age.
  Covers FR-005, FR-006, SC-003.
- [ ] T015 [US2] Implement DiscoveryCache.load/publish in mole_pkg/discovery.py
  using canonical data-model.md DiscoveryRecord.schema, DiscoveryRecord.scope,
  DiscoveryRecord.entitlement_tier, DiscoveryRecord.entitlement_observed_wall,
  DiscoveryRecord.observed_wall, DiscoveryRecord.boot_id,
  DiscoveryRecord.observed_mono and DiscoveryRecord.candidates. Implement finite
  size/count/permissions/atomic-fsync constraints, and current-policy refiltering.
  Implement data-model.md RejectionRecord.scope, RejectionRecord.transaction_id,
  RejectionRecord.kind and RejectionRecord.observed_wall with durable pre-operation
  pending state, authorized clearing and protection against stale removal.
  Covers FR-005, FR-006.
- [ ] T016 [US2] Add red provider/orchestration tests in tests/test_proton_worker.py
  and tests/test_validated_recovery.py exercising full recovery with unavailable
  authentication/discovery control plane and an existing scoped certificate;
  distinguish explicit rejection, expired certificate, changed session/account/
  entitlement, empty raw versus valid withdrawal, and absent binding components.
  Include cold-process offline preparation, rejection then timeout/restart,
  pre-operation persistence failure and no age extension from old entitlement.
  Covers FR-005, FR-006, FR-007, SC-003.
- [ ] T017 [US2] Implement ProtonProvider.prepare_recovery and scoped transient
  discovery fallback in mole_pkg/providers/proton.py and proton_worker.py. Extend
  only the bounded allowlisted account GET operation needed to warm verified
  entitlement; no new password loop or credential rewrite on cache use. Integrate
  preparation in mole_pkg/mole.py without forcing live refresh before fallback.
  Covers FR-005, FR-006, FR-007.
- [ ] T018 [US2] Run targeted offline-provider and full recovery tests, including
  an in-flight catalogue/certificate/policy change, and record cache rejection
  and successful recovery evidence in the private run. Covers FR-006, FR-007,
  FR-008, FR-015, SC-003.

## Phase 4: US3 - Component Health And Local Repair (P2)

- [ ] T019 [US3] Add red tests/test_validated_recovery.py for DNS-only failure
  with working transport, supervised DNS repair budget/cooldown, mapping-only
  failure, blocked client API and failing tracker hook. Assert unrelated recovery
  and repeated tracker calls do not occur. Add tests/test_dns.py and
  tests/test_services.py coverage for repair-only cached blocklist startup,
  download-descendant cleanup, missing required cache, listener timing and
  DoT-disabled/external resolver ownership. Covers FR-008, FR-010, FR-011, SC-005.
- [ ] T020 [US3] Implement bounded DNS health/local worker repair and component
  decisions in mole_pkg/mole.py, mole_pkg/services/dns.py and
  mole_pkg/services/dns_main.py, including
  owned child groups and bounded repair-only startup. Retain mapping/client supervision;
  do not change DNS upstream policy or add MaM code to core. Covers FR-008,
  FR-010, FR-011, FR-012.
- [ ] T021 [US3] Add red tests/test_api_main.py and tests/test_utils.py for
  additive fields, expiry/restart/malformed evidence, legacy null values,
  existing field meanings and no fabricated tracker success. Covers FR-010,
  FR-011, FR-013, SC-005.
- [ ] T022 [US3] Implement data-model.md RecoveryHealth.authorization_ready,
  RecoveryHealth.gate_open, RecoveryHealth.dns_ready,
  RecoveryHealth.discovery_source, RecoveryHealth.cache_age_seconds,
  RecoveryHealth.next_retry_in_seconds, RecoveryHealth.recovery_reason and
  RecoveryHealth.workload_ready in mole_pkg/utils.py, mole.py and
  services/api_main.py per contracts/status.md; no high-cardinality metrics.
  Covers FR-009, FR-010, FR-011, FR-013.

## Phase 5: Cross-Cutting Acceptance And Review

- [ ] T023 Extend tests/test_review_regressions.py and existing PIA/legacy/config/
  API regressions for opt-in behavior and both runtime entrypoints; run the full
  unittest suite and record exact warnings/results. Covers FR-003, FR-013,
  FR-015, SC-006.
- [ ] T024 Implement explicit opt-in tests/network/validated_recovery_acceptance.py
  with owned lifecycle/preflight/cleanup, synthetic packet positive controls,
  gate/cgroup/IPv6/expiry/controller-death/inherited-socket cases, and existing
  late-grant-after-proof-expiry with the controller already dead,
  iptables/wg-quick interoperability per quickstart.md. Never use live namespaces,
  Docker networks or credentials. Covers FR-004, FR-008, FR-012, SC-004, SC-005.
  Use the runner-only dependency injection seam from quickstart.md, never a
  production option disabling global-address/TLS/authorizer validation. Test that
  production entrypoints cannot activate the synthetic seam.
- [ ] T025 Run the isolated network acceptance matrix from quickstart.md in
  approved QA storage and preserve compact captures/counters privately. Verify
  no task-owned namespaces/interfaces/cgroups remain. A missing capability or
  failed positive control blocks deployment. Covers FR-004, FR-012, FR-015,
  SC-004, SC-005, SC-006.
- [ ] T026 Update README.md, config.example and source version/release notes only
  for verified feature behavior; explain opt-in backend/delegation prerequisites,
  privacy and evidence limits, status contract and fail-closed rollback.
  Covers FR-003, FR-013, FR-014, FR-016.
- [ ] T027 Obtain independent source/security review of implementation versus
  spec.md/plan.md/contracts, resolve high-severity findings and rerun affected/full
  tests before proposing a merge or release. Covers FR-015, SC-006.
- [ ] T028 Prepare/review the host-only validator, candidate list, backup/rollback
  and controlled production acceptance in the companion outside this public
  repository. No live restart, delegation change or pool expansion before owner
  approval. Covers FR-004, FR-011, FR-014, FR-016, SC-005.
- [ ] T029 After separate owner rollout approval, execute the companion's controlled
  production recovery and record qBittorrent PID/file continuity, gate denial/
  recovery, DNS, forwarding, actual transfers, dependent app access and separate
  tracker outcomes in private evidence. Do not mark SC-005 passed from preparation
  or synthetic captures. Covers FR-012, FR-016, SC-001, SC-005.

## Dependencies And Execution

T001 -> T002/T003 -> US1 -> US2 -> US3 -> cross-cutting acceptance. Within each
test/implementation pair, tests fail first and pass after. US2 depends on US1's
canonical Candidate; US3 consumes validated evidence and can ship only after
enforcement exists. Do not parallelize writers to providers/proton.py, mole.py,
network.py or shared tests. A reviewer may run read-only alongside independent
documentation work. Each completed source deliverable can be committed only
after verification with the owner's GitHub noreply identity; no automatic push.

MVP is US1 with live discovery and real kernel acceptance; cache and component
work remain required for the complete approved feature. Separate implementation,
network acceptance, merge/release and production approvals; none is inferred from
this task list. FR-001..FR-016 and SC-001..SC-006 have explicit task coverage.
