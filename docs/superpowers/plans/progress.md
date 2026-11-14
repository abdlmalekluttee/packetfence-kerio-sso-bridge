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

Final review: fresh read-only reviewer, base eae426b through 6549f72. Six Important
findings; no Critical or Minor findings. All six accepted after deterministic
reproduction. One fix pass; no second review, as required by executing-plans.

Final: fixed target deletion/policy publication races —
test_deleted_target_cannot_receive_late_login and
test_policy_save_waits_for_old_policy_mutations RED→GREEN, suite 60/60.
Final: fixed host-wide IPv4/IPv6 alias collisions —
test_expiring_alias_preserves_other_active_lease and
test_alias_with_different_identity_refuses_host_rebinding RED→GREEN, suite 60/60.
Final: fixed canonical-domain Stop classification —
test_equivalent_domain_forms_stop_same_lease RED→GREEN, suite 60/60.
Final: fixed expiry overwriting concurrent renewal —
test_renewal_wins_over_stale_expiry_read RED→GREEN, suite 60/60.
Final: fixed response-header trickle deadline — real TLS loopback
test_response_header_trickle_obeys_absolute_deadline RED→GREEN (1.217s before
fix exceeded the 0.7s assertion for a 0.2s deadline), suite 60/60.
Final: fixed full-host-list amplification —
test_periodic_sweep_shares_host_snapshot RED (100 reads)→GREEN (shared snapshot),
suite 60/60. Canonical address indexing avoids repeatedly parsing the full list.
Final: closed test gaps for durable receive/final-state failure and a Stop during
an actual delayed failing login; all passed with existing durable/generation logic.

Final: Ruling: appliance-specific behavior remains a live acceptance gate — no
appliances available; do not claim production compatibility — cost: deployment
must verify versions, permissions, persistence and traffic policy.
Final: Ruling: container runtime and Python 3.12 remain CI/lab checks — Docker
daemon unavailable and only Python 3.13 installed — cost: build/runtime and 3.12
execution are unverified locally; full Compose and real entrypoint checks passed.
Final: Ruling: independent Kerio admin changes cannot be atomic with Users.set —
API lacks revision guards; retain reread/readback and maintenance procedure —
cost: a last-moment external edit can still race with the minimal update.
Final: Ruling: same-identity upstream ordering remains limited — no session
sequence in the generic protocol — cost: delayed indistinguishable events need
upstream extension or authoritative session lookup for stronger guarantees.
Final: Ruling: shared-state replicas remain unsupported — one writer/service
instance is the supported deployment — cost: no active-active high availability.
Final: Ruling: upstream PacketFence TLS behavior is not changed here — external
codebase; document management isolation/tunneling — cost: upstream transport
authenticity still depends on the deployment controls.
Final: Ruling: retire legacy environment-only target seeding — explicit validated
persisted targets replace implicit setup — cost: those installations must migrate.
Final: minor (deferred): none.

Task 5: complete — 60/60 unittest tests, Node GUI, compile, Bash syntax and
whitespace checks PASS. Full Compose config and real loopback entrypoint PASS.
Local branch retained for the user; no push, merge, publication or live deployment.
The referenced finishing-a-development-branch helper is unavailable; delivery
uses the authorized local branch plus a source archive and preserved plan/ledger.
