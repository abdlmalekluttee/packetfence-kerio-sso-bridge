# Prompt reconnect implementation plan

> **For agentic workers:** Use executing-plans to implement this plan inline, followed by independent code review.

**Goal:** A new authenticated PacketFence event promptly rechecks a missing host without flooding Kerio or relogging a correct user.

**Architecture:** Keep normal exponential retries. Active events open a ten-second presence-check window; only host-not-present errors can shorten their pending retry, at most once per IP every five seconds. Use the existing shared two-second host snapshot and target failure backoff. Persist deadlines with the existing JSON lease state and update failure timing against the latest lease under its transaction lock.

**Tech Stack:** Python standard library, SQLite, existing Kerio JSON-RPC client and unittest network-boundary appliance double.

**Spec:** User request of 15 November 2026: fix reconnect delay without overhead/flooding. Observed 10.44.70.46 became visible at 00:43:38 but waited until 00:46:02 because an old missing-host retry remained in effect.

## Global constraints

- No forced disconnect or logout of active users for testing.
- Correct identities, Stop semantics, manual override policy, domain routing, API failure backoff and periodic reconciliation remain intact.
- No new dependencies or configuration knobs; keep current production settings and state through deployment.
- Do not retry Docker Hub publishing; user deferred that separate token issue.

## Review focus

- Concurrent duplicate events must not cause duplicate presence probes or logins.
- An event arriving while a probe is in flight must not lose its follow-up window.
- Events arriving before Kerio sees traffic need a bounded follow-up without another event.
- Old persisted leases and restart during cooldown must remain compatible.
- API outages, manual conflicts and stale Stop events must not bypass their protections.

### Task 1: Bounded event-driven missing-host recovery

**Files:** Modify bridge/engine.py, README.md and docs/operations.md; create tests/test_reconnect.py.

**Interfaces:** Existing Engine.handle(method, params), tick(), StateStore.update and KerioClient.host_by_ip remain unchanged. Optional presence deadlines are JSON lease metadata; absent fields are supported.

- [ ] Write tests for Start and Update reconnect after a 300-second missing-host delay, visibility just after the first probe, concurrent duplicates, many missing IPs sharing one snapshot, restart/legacy state, no events retaining normal backoff, and non-presence failures retaining backoff. Assert actual RPC counts and identity mutations through the real engine/client.
- [ ] Run `python -m unittest tests.test_reconnect -v`; observe reconnect assertions fail on the original engine.
- [ ] Implement the five-second cooldown and ten-second follow-up window only for active missing-host reconciliation, preserving normal failures and lease generation checks.
- [ ] Run `python -m unittest discover -q` and `node tests/test_ui.js`; expect all tests pass. Document event-based timing and limits.
- [ ] Commit, obtain independent review, address important findings with failing tests first.

### Task 2: Release and verify

**Files:** Repository PR plus task-local rollout/report files outside the repository.

**Interfaces:** Consume Task 1 commit; deploy a locally built image using the existing Compose files and current data, credentials, certificates and manual override setting.

- [ ] Push feature branch, create PR, check test CI and merge after passing review/checks, using the user's standing authorization.
- [ ] Build image before a brief bridge restart, preserve durable state and rollback copy, verify health/configuration and existing Kerio users afterward.
- [ ] Use isolated temporary state and read-only live Kerio access to reproduce the old missing-host retry for the already-correct phone and demonstrate prompt verification and no duplicate mutations. Report that this is not a physical reconnect test.
