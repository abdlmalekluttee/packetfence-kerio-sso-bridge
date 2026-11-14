# Reliable SSO Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Eliminate repeated login churn and safely reconcile PacketFence identities, with an optional exact-IP manual-assignment override.

**Architecture:** A small stdlib package separates Kerio API contracts, validated configuration, durable SQLite reconciliation, and the bounded HTTP/GUI boundary. Synchronous acknowledgement shares the same generation-aware reconciliation path as background retry/expiry; no per-event PacketFence polling or unbounded queue.

**Tech Stack:** Python 3.12+, unittest, sqlite3, http.client, http.server, plain browser JavaScript, Docker Compose.

**Spec:** `docs/superpowers/specs/reliable-sso.md`

## Global Constraints
- Python >=3.12, standard-library runtime, Docker non-root UID 10001.
- `override_manual` defaults false; remove exact conflicting IP only.
- Verify identity before mutation; never send empty ActiveHosts.logout IDs.
- 30s verified cache, 2s host snapshot, 60s reconciliation, 3600s fallback lease;
  configurable bounded retries 2..300s and 10000 stored mappings.
- No remote push/publish/deploy or live firewall changes.

## Review Focus
- Same username in different domains must not be conflated (task 1 identity test).
- A delayed failed login followed by Stop cannot resurrect access (task 3 race test).
- Shared/manual auto-login rules must not be broadened or deleted (task 2 tests).
- Disk failure must not acknowledge a change absent from durable state (tasks 3/4).
- Silent TLS clients and cached GUI credentials cannot bypass boundaries (task 4).

## File responsibilities
- `bridge/kerio.py`: validated JSON-RPC, pagination, identity and exact-IP overrides.
- `bridge/registry.py`: validated atomic target settings, snapshots, client reuse.
- `bridge/state.py`: durable bounded SQLite desired-state store.
- `bridge/engine.py`: idempotent generation-aware reconciliation, expiry/retries.
- `bridge/server.py`: bounded transport, auth/CSRF, dispatch, startup validation.
- `bridge/ui.html`: safe management UI, policy toggle, operational status.
- `pf_kerio_sso_bridge.py`: backward-compatible executable entry point.
- `tests/`: deterministic API fixtures, integration and concurrency regressions.
- deployment files, README, `docs/operations.md`: secure packaging and runbook.

### Task 1: Kerio read and session contracts
**Files:** Create bridge/kerio.py, bridge/__init__.py, tests/test_kerio.py, tests/helpers.py.
**Interfaces:** `KerioClient(cfg)`, `call(method, params) -> dict`, `host_by_ip(ip, fresh=False) -> dict|None`, `matches(host, username) -> bool`, `transaction()` context, `login_user(host_id,user)`, `logout(host_id)`.
- [x] Write tests: matching full domain (different domain false), canonical IPv6 aliases,
  pagination, session expiry retry, malformed/mismatched response failure, empty
  logout refusal, default TLS verification and CA settings.
- [x] Run `python -m unittest tests.test_kerio -v`; expect failures for missing behavior.
- [x] Implement bounded JSON-RPC responses, cookie handling, no redirects,
  request deadline, response validation, pagination and short host snapshot cache.
- [x] Run tests; expect all pass. Commit `feat: add validated Kerio API client`.

### Task 2: Optional exact-IP manual conflict override
**Files:** Modify bridge/kerio.py; create tests/test_manual.py.
**Interfaces:** `resolve_user(username) -> (domain_id,user)`, `prepare_conflict(host, ip, username) -> None` raises descriptive error when unsafe; emits audit event after verified Users.set.
- [x] Write tests for override disabled (no Users.set/logout), enabled removes only
  one exact address, no mutation of desired user's assignment, unrelated settings
  preserved, missing target user, per-item errors, unsafe groups/MAC/template,
  configuration changed between reads, and post-write readback mismatch.
- [x] Run `python -m unittest tests.test_manual -v`; expect assertion failures.
- [x] Implement user/domain lookup on conflicts only, minimal autoLogin update,
  independent readback and result.errors checks. Never use Users.remove.
- [x] Run tasks 1/2 tests; expect pass. Commit `feat: add opt-in manual IP conflict override`.

### Task 3: Durable idempotent synchronization
**Files:** Create bridge/state.py, bridge/engine.py, tests/test_engine.py.
**Interfaces:** `StateStore(path)`, `Engine(registry, store, clock=time.time)`,
  `handle(method, params) -> str|None`, `tick()`, `status()`, `start()/close()`.
  Registry contract `candidates(ip) -> list[(id,client)]`, `get_client(id)`.
- [x] Write tests for duplicate no-op (zero mutation), cache reduces reads, renew
  expiry, identity replacement, old-user Stop ignored, failed Stop non-OK/retry,
  expiry/restart cleanup, simultaneous Start/Stop, bounded capacity/backoff,
  ambiguous targets, unknown Stop only matching owner, stale host MAC refusal.
- [x] Run `python -m unittest tests.test_engine -v`; expect missing behavior failures.
- [x] Implement SQLite transactional desired state, striped operation locks,
  monotonically increasing generations, fresh reads before writes, target pinning,
  single background worker, positive cache, persisted backoff and expiry.
- [x] Run full suite; expect pass. Commit `feat: reconcile SSO leases without login churn`.

### Task 4: Secure configuration, HTTP and GUI
**Files:** Create bridge/registry.py, bridge/server.py, bridge/ui.html;
  replace pf_kerio_sso_bridge.py; create tests/test_registry.py, tests/test_server.py,
  tests/test_ui.js.
**Interfaces:** `Registry(path).upsert(data)/delete(id)/public_list()/candidates(ip)/get_client(id)`,
  `create_server(address, registry, engine, settings)`, `main()`.
- [x] Write tests for failed save preserving snapshot, invalid CIDRs/types/hosts,
  password omission, client reuse, secure defaults; HTTP auth, foreign origin,
  CSRF, JSON envelope/type/size checks, silent TLS peer, HTTP health and safe GUI
  name rendering/toggle save using DOM stub or browser.
- [x] Run suites and Node GUI check; expect failures before implementation.
- [x] Implement atomic 0600 JSON writes/0700 dirs, worker-limited HTTP with TLS
  negotiation after accept, startup config validation, CSRF token/custom header,
  safe DOM listeners, policy checkbox and status endpoint. Preserve legacy JSON.
- [x] Run full suite; expect pass. Commit `fix: harden management and transport boundaries`.

### Task 5: Deployment, documentation and release verification
**Files:** Modify Dockerfile, docker-compose.yml, deploy.sh, .env.example,
  .github/workflows/publish.yml, .gitignore; add .dockerignore,
  .github/workflows/test.yml, docs/operations.md, tests/test_deploy.py.
- [x] Write/run literal dotenv serialization regression and startup subprocess
  checks. Verify existing config survives deployment rather than rewriting it.
- [x] Package new modules/UI; real health probe; readonly container with tmpfs,
  no-new-privileges and caps dropped; tests gate publication, Python 3.12/3.13 CI.
- [x] Document exact API assumptions, source links, option risks, trigger/role
  configuration, unknown timeout policy, migration, backups, rollback, live lab
  matrix, cached verification window and generic-protocol ordering limits.
- [x] Run `python -m unittest discover -v`, `node tests/test_ui.js`, compile checks,
  Compose validation, container checks if engine is available, git diff --check.
- [x] Commit `chore: document and verify reliable SSO deployment`.
- [x] Fresh independent whole-branch review; reproduce/fix significant findings,
  rerun full suite, retain plan and ledger evidence. Deliver branch and package.

## Execution notes
User explicitly requested immediate implementation; no planning approval pause.
Dedicated fresh clone on feat/reliable-sso; no preexisting worktree or user edits.
Baseline has zero tests. Skill shell ledger helpers reference missing files;
maintain the equivalent progress ledger directly rather than block execution.
