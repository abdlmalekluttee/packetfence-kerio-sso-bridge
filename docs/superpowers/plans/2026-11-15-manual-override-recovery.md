# Manual Override Recovery Implementation Plan

> **For agentic workers:** Use executing-plans inline and one independent final reviewer.

**Goal:** Confirm exact-IP changes and recover safely from partial override operations without repeated logouts.

**Architecture:** Kerio client implements configuration confirmation and proof-checked recovery. The engine journals proof in its existing durable lease, schedules settling/retries, and caps mutations. No new service or polling loop.

**Tech Stack:** Python standard library, SQLite, Kerio JSON-RPC, PacketFence read-only observer.

**Spec:** `docs/superpowers/specs/manual-override-recovery.md`

## Global Constraints

- Existing correct sessions are untouched; no manufactured live conflicts.
- Preserve unrelated policy and users; never confirm configuration solely on a read. Persistent revisions require a 35-second stability observation before our write; this reduces concurrency risk but cannot establish exclusive ownership.
- Five-second settling, 60-second recovery retry spacing, two writes/two bind attempts maximum, 15-minute evidence lifetime.
- Evidence must survive restart; changed ownership/configuration invalidates it.
- Existing source validation and disabled-override safeguards remain mandatory.

## Review Focus

- Configuration confirmation false/malformed/expired-session responses cannot authorize logout (client tests).
- Crash after write but before confirmation or host bind cannot bypass proof validation (recovery tests).
- New Stop/identity/policy/host invalidates pending work (concurrency/state tests).
- Reappearing automatic login cannot produce a logout loop (bounded retry test).
- Matching sessions and unrelated host aliases remain protected (existing and regression tests).

### Task 1: Confirmation and recovery proof

Files: `bridge/kerio.py`, `tests/helpers.py`, `tests/test_kerio.py`, `tests/test_override_recovery.py`.
Interfaces: `prepare_conflict(..., recovery=None, checkpoint=None)` and a scoped administrative-session refresh.
- [x] Write failing configuration-confirmation and partial-write regression tests.
- [x] Implement confirmation protocol, strict proof validation and independent readback.

### Task 2: Durable scheduling and bounded host changes

Files: `bridge/engine.py`, `tests/test_override_recovery.py`, `docs/operations.md`.
Consumes proof/checkpoint; persists `manual_recovery` inside lease rows.
- [x] Write failing tests for deferred, restart-safe recovery, retry limits and concurrent cancellation.
- [x] Implement scheduling, counters and fresh post-logout checks.
- [ ] Run full Python/GUI suites and independent review; fix findings.

### Task 3: Release and verify

- [ ] Push PR, pass CI, merge and stage the merged image.
- [ ] Verify matching production sessions with an isolated read-only trial.
- [ ] Deploy with consistent state backup and existing observer configuration.
- [ ] Confirm recovered target remains correct, other sessions unchanged and no new error loop.
