# Explicit domain aliases and pending-session recovery

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Resolve configured short realms without changing already-correct Kerio sessions, and diagnose pending hosts without forcing active users offline.

**Architecture:** A validated per-target domain_aliases dictionary maps explicit short realm names to full domains. Per-target domains selects which identities that firewall serves, intersected with its subnet scope. Canonicalization is shared by comparison, lookup, event equivalence and API login; it adds no network requests. Domains excluded from every configured target are acknowledged without remote actions, and their old pending records are completed as ignored. Existing target pins never silently migrate between firewalls.

**Tech Stack:** Python 3.12+ standard library, SQLite, plain JavaScript, Docker Compose.

**Spec:** User request: fix pending users, handle lab@hiss correctly, test without disturbing active users; existing docs/superpowers/specs/reliable-sso.md.

## Global Constraints

- No fuzzy realm matching, automatic suffix guessing, or cross-domain fallback.
- Preserve all correctly authenticated active sessions; no bulk logout or broad manual override.
- Domain alias changes are identity changes and use the existing active-lease configuration guard.
- Keep CPU/API work bounded; canonicalization uses local configuration only.

## Review Focus

- Equivalent UPN and DOMAIN\\user names must share comparison and Stop semantics.
- Unmapped short realms and different full domains remain distinct.
- Malformed mappings, duplicate case-folded keys, chains and cycles are rejected before save.
- Existing configurations default to no aliases; GUI edits retain saved mappings.
- Correct live users require zero login/logout/configuration writes after canonicalization.

## Task 1: Explicit alias support

**Files:** bridge/kerio.py, bridge/registry.py, bridge/server.py, bridge/ui.html, bridge/ui.js, tests/test_kerio.py, tests/test_registry.py, tests/test_engine.py, tests/test_server.py, tests/test_ui.js, docs/operations.md.

**Interfaces:** normalized_user(name, default_domain='', domain_aliases=None) returns a canonical string. Target domain_aliases is a dictionary of short realm to full DNS domain, default {}. GUI accepts a JSON object and shows validation errors without saving.

**Updated user scope:** Ignore library.local for now because it uses a different Kerio. Configure FSSI for hiss.local and tanasuh.local. Add per-target domains (empty means any, local selects unqualified local users), KerioClient.accepts_user(name), Registry.ignores_user(name), and Registry.candidates(ip, user=None). Disabled targets retain domain ownership and produce pending errors rather than being silently ignored. Domain policy edits use the active-lease guard.

- [x] Write failing tests for alias comparison, lookup, equivalent Stop, repeated renewals without extra calls, mapping validation/persistence and active-lease guard.
- [x] Write failing routing tests for domain/subnet intersection, excluded-domain no-ops, ignored historical pending records, disabled targets and pinned cross-target conflicts.
- [x] Run focused tests and confirm failures are the missing behavior.
- [x] Implement canonicalization and validation; wire GUI and identity guard; document explicit mappings.
- [ ] Run full Python and JavaScript suites, inspect diff, obtain independent review, push PR, verify CI and merge.

## Task 2: Diagnose and recover pending entries

- [x] Capture fresh pending rows, PacketFence owners and Kerio host/user identity summaries; identify missing-host network path separately from name errors.
- [x] Verify configured alias destinations exist in Kerio and short realms exist in PacketFence configuration. Use guarded real-client tests that prohibit mutations on already-correct hosts.
- [ ] Back up the running deployment, install the merged image and explicit aliases without changing targets or active session ownership; preserve durable state.
- [ ] Retry and monitor affected entries. Correct prerequisites only when evidence identifies the cause and the change preserves unrelated active users. Report unresolved external prerequisites rather than hiding pending failures.

