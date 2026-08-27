# qBittorrent HTTP Passthrough Implementation Plan

> **For Codex:** Follow test-driven development and verify each checkpoint before proceeding.

**Goal:** Add an optional MOLE-owned Nginx HTTP passthrough that eliminates stale qBittorrent Web API connection reuse while preserving the current listener contract.

**Architecture:** Keep `qbittorrent-passthrough.service` and route its execution through one generated wrapper. The wrapper dispatches to the existing `socat` relay or an isolated foreground Nginx process according to validated configuration.

**Tech Stack:** Python 3, Bash, systemd, Nginx, pytest.

---

### Task 1: Configuration Contract

- [x] Add failing tests for the default, supported modes, and invalid mode validation.
- [x] Add `Config.qb_passthrough_mode` with a `socat` default.
- [x] Reject unsupported values with a useful validation error.
- [x] Run focused configuration tests.

### Task 2: Runtime Rendering

- [x] Add failing tests for the generated wrapper and systemd unit.
- [x] Make the wrapper dispatch on `QB_PASSTHROUGH_MODE`.
- [x] Preserve the existing `socat` command and bind semantics.
- [x] Generate isolated Nginx configuration with explicit connection-close, host, body-size, buffering, and timeout directives.
- [x] Add a systemd runtime directory and execute the wrapper from the service.
- [x] Run focused rendering tests.

### Task 3: CLI Reconciliation

- [x] Add failing tests for mode-specific dependency checks and idempotent service reconciliation.
- [x] Require `socat` only in socat mode and `nginx` only in nginx mode.
- [x] Make `mole qbittorrent passthrough` regenerate managed artifacts before starting or reporting status.
- [x] Expose the selected passthrough mode in qBittorrent status.
- [x] Run focused CLI tests.

### Task 4: Documentation

- [x] Add the new setting to `config.example`.
- [x] Update README setup, upgrade, behavior, and rollback guidance.
- [x] Correct the changelog claim that TCP keepalive prevents HTTP resets.

### Task 5: Repository Verification

- [x] Run all focused tests.
- [ ] Run the complete test suite and compare with the recorded baseline.
- [ ] Inspect the final diff for scope, security, and compatibility.
- [ ] Commit and publish the branch for review.

### Task 6: Guarded Host Rollout

- [ ] Back up the live MOLE config, passthrough unit, and drop-ins.
- [ ] Install the tested repository version without restarting qBittorrent or MOLE.
- [ ] Set this host to `QB_PASSTHROUGH_MODE=nginx`.
- [ ] Reconcile and validate the service unit before switching the listener.
- [ ] Restart only `qbittorrent-passthrough.service`.
- [ ] Verify MOLE, WireGuard, qBittorrent, Arr clients, Qui, and the external torrent port.
- [ ] Observe logs across multiple Arr health-check cycles and roll back if regressions appear.
