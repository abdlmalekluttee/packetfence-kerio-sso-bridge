# SDD ledger — plan: docs/superpowers/plans/2026-11-14-reliable-sso.md

Base: eae426ba59d1eca1f2250cf24c5423831ed3f938; branch feat/reliable-sso.
Baseline: unittest discovery, 0 tests; existing production issues reviewed.
Pre-flight: task 3 consumes task 1 KerioClient and task 4 Registry contract;
test fixtures implement that same boundary. Task 4 HTTP consumes Engine.handle.
Ruling: dedicated fresh clone rather than extra linked worktree — no existing
checkout was attached; no user edits at risk — cost: separate local clone.
Ruling: follow immediate-execution instruction over skill approval handoff.
Ruling: maintain ledger directly; shell helper dependency is absent — cost:
manual task/check tracking, retained with deliverable.
Ruling: exact-IP override off by default; broad shared rules refuse mutation —
limits automation for MAC/group assignments but prevents unrelated disruption.
Ruling: no per-event PacketFence polling; generic protocol has no session sequence,
so same-identity out-of-order sessions remain a documented integration limitation.
Task 1: complete — initial missing-module RED; 7/7 client contract tests GREEN. Runtime uses direct HTTPS without redirect/proxy credential forwarding.
Task 2: complete — missing prepare_conflict RED; full suite 16/16 GREEN. Exact-IP removal verified, broad rules and disabled policy refuse writes.
Task 3: complete — missing engine RED; full suite 29/29 GREEN. Durable generation checks, positive cache, retry backoff, expiry and manual-override end-to-end verified.
Task 4: complete — missing modules/UI RED; full suite 42/42 and Node GUI GREEN. Original TLS hang repro now covered by silent-peer regression. Fixed bounded-body drain after Windows reset exposed by HTTP test.

Task 5: implementation complete — dotenv/config/startup regressions and new shared-backoff, deadline and active-target guard tests RED→GREEN; full suite 49/49 and Node GUI PASS. Compile and Bash syntax PASS. Docker daemon unavailable; container build/runtime deferred to added CI and live-lab runbook.
