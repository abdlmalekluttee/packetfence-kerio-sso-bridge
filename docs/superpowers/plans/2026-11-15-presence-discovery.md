# Shared missing-host discovery plan

> Execute inline with test-driven development and independent review.

**Goal/spec:** Morning operational audit found devices becoming visible after the ten-second event window still wait minutes for a 300-second retry. Detect these arrivals within the next shared discovery pass without per-user polling or repeated login.

**Architecture:** When active missing-host leases exist, the worker shares one Kerio host snapshot per target every five seconds. It wakes only leases whose IP is now visible, retaining generation, expiry, routing, MAC and ownership checks. Normal missing-host retry timers do not change while the host stays absent; API failures and manual conflicts do not qualify. Existing client snapshot caching, serialization and target outage backoff remain in force.

**Files:** bridge/engine.py; tests/test_reconnect.py; README.md; docs/operations.md.

**Review focus:** many pending IPs share a snapshot; no scans without missing hosts; API circuit breaker respected; stale scans cannot alter a newer Stop or identity; multi-target ambiguity retains protection; login remains idempotent.

1. Add failing tests for a host arriving after the event window with no further events, 100 absent leases sharing reads, healthy-only targets, failures/manual rules, stale generation and multi-target discovery.
2. Add a bounded per-target discovery schedule and wake visible pending rows without changing other failure schedules.
3. Run full Python and GUI suites; obtain read-only independent review and fix important findings with RED/GREEN verification.
4. Create/merge PR after CI, build locally and deploy using preserved state/configuration and a rollback backup. No forced logout of unrelated active users.
5. Verify fresh counts, corrected manual users, stable active sessions and resource use. Report remaining absent devices, active stale PacketFence ownership concerns, disk pressure and unrelated antivirus-update failures.
