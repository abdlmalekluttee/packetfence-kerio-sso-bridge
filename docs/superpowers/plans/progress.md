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
`nTask 1: complete — initial missing-module RED; 7/7 client contract tests GREEN. Runtime uses direct HTTPS without redirect/proxy credential forwarding.
