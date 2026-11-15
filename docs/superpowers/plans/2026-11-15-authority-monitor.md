# PacketFence Authority Monitor Implementation Plan

> **For agentic workers:** Use executing-plans; implement inline with one independent final review.

**Goal:** Automatically recognize obsolete PacketFence IP leases without interrupting existing Kerio sessions.

**Architecture:** Optional API observer supplies bounded cached source checks to the existing reconciler. Stale bindings are held and retired only after repeated source evidence and Kerio absence. Existing event and host-presence paths remain authoritative only within these checks when configured.

**Tech Stack:** Python standard library, SQLite, PacketFence 15 API, Kerio JSON-RPC, Docker.

**Spec:** `docs/superpowers/specs/packetfence-authority.md`

## Global Constraints

- No PacketFence node/IP writes; NODES_READ service account only.
- Preserve any Kerio host while source ownership is obsolete or uncertain.
- Two stale observations separated by 60 seconds, plus fresh Kerio absence, before retirement.
- TLS validation or explicit certificate pin; no credential logging.
- Python 3.12/3.13; bounded requests and response sizes; API outages retain sessions.

## Review Focus

- Partial/truncated API results must fail closed (client tests).
- Changed MAC/user and realm aliases must not validate stale leases (client/engine tests).
- In-flight newer events must prevent stale cleanup (engine concurrency test).
- Existing portal/API login times must survive stale source observations (engine/live read checks).
- Unknown source or API outage must never become absence evidence (client/engine tests).

### Task 1: Source client

Files: `bridge/packetfence.py`, `tests/test_packetfence.py`.
Interfaces: `PacketFence.refresh(rows)`, `PacketFence.check(row, canonicalize) -> current/stale/unknown`; clock injected; sanitized `error` status.

- [ ] Write failing tests for identity, expired/current records, partial results, API failure, caching and bounds.
- [ ] Implement batch search, authentication, TLS/pinning, strict parsing and backoff.
- [ ] Run client tests and full suite.

### Task 2: Safe reconciliation

Files: `bridge/engine.py`, `bridge/server.py`, `bridge/ui.js`, `tests/test_authority.py`, `.env.example`, `Dockerfile`.
Consumes source client; exposes waiting/held/failed status and optional configuration file.

- [ ] Write failing tests for preserved active hosts, absent stale retirement, unknown source, concurrent renewals and unusable addresses.
- [ ] Implement source guards, retirement confirmation, address filtering and status display.
- [ ] Run Python and GUI suites; document setup and operational limits.

### Task 3: Release and live verification

- [ ] Provision a dedicated NODES_READ account through PacketFence's local API; verify reads and denied writes without changing nodes.
- [ ] Review whole branch, fix findings, push PR, pass CI, merge.
- [ ] Stage image, preserve state/config, deploy with rollback, inspect live counters and unchanged sessions.
- [ ] Report pending/held IPs accurately; distinguish upstream uncertainty from bridge failures.
