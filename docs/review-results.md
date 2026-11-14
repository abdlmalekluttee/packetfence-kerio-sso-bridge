# Technical review and implementation verification

Reviewed upstream base: `eae426ba59d1eca1f2250cf24c5423831ed3f938`.
Implementation branch: `feat/reliable-sso`. No remote push, publication,
deployment, or live appliance mutation was performed.

The initial source review covered authentication/SSO flow, PacketFence event
contracts, Kerio API usage, configuration and management UI, deployment, tests,
security, operational failure modes and maintainability. The resulting rewrite
separates these responsibilities into a small standard-library Python package.
The [specification](superpowers/specs/reliable-sso.md) links the primary API
sources; the [plan](superpowers/plans/2026-11-14-reliable-sso.md) and
[execution ledger](superpowers/plans/progress.md) record implementation decisions.

## Final independent branch review

A fresh reviewer audited base through `6549f72afbde77f426d82bdc0e0968a387545348`.
All 49 then-existing Python tests passed, but six important issues were reproduced.
No critical or additional minor issues were identified. Each issue below was
fixed in one subsequent pass with a failing regression observed before the fix.
The reviewer did not re-review the fix pass; the expanded tests verify it.

| Priority | Reproduced issue and impact | Fix and current source citation | Regression |
| --- | --- | --- | --- |
| P1 | Deleting a target after selection but before pinning allowed a late login with no remaining revocation target. Disabling override could acknowledge before an old-policy removal. | Stable bounded target-operation locks coordinate current-client validation, durable pinning, guarded publication, deletion and in-flight writes. `bridge/registry.py:98`, `bridge/server.py:201`, `bridge/engine.py:123`. | `tests/test_regressions.py:139`, `:158` |
| P1 | IPv4/IPv6 leases sharing one Kerio host could revoke or replace each other. | Preserve compatible live sibling leases on Stop/expiry; refuse conflicting identities before mutation. `bridge/engine.py:210`. | `tests/test_regressions.py:30`, `:39` |
| P1 | Start `alice`, Stop `alice@example.test` returned OK while leaving access active despite an explicit matching default domain. | Use the selected target's canonical username mapping for stale-Stop classification. Different domains remain distinct. `bridge/engine.py:53`. | `tests/test_regressions.py:46` |
| P1 | A stale expiry snapshot overwrote a concurrent durable renewal and logged out a valid session. | Recheck current generation, desired state and expiry atomically inside the SQLite update. `bridge/engine.py:123`. | `tests/test_regressions.py:52` |
| P1 | Trickling TLS response headers bypassed the absolute transaction deadline and could stall reconciliation. | A deadline timer shuts down the actual connection during header/body operations, in addition to inactivity and size limits. `bridge/kerio.py:89`. | Real loopback TLS test, `tests/test_regressions.py:185` |
| P1 | A sweep of 100 correct sessions performed 100 full-list API reads. | Separate per-lease cache bypass from shared snapshot refresh; index canonical IP aliases once per snapshot. Fresh reads remain before destructive changes. `bridge/engine.py:123`, `bridge/kerio.py:215`. | 100-host sweep, `tests/test_regressions.py:21` |

## Verified behavior

- Matching full-domain identity causes no login/logout. Repeated events inside
  the verified-cache window cause no additional Kerio request.
- Manual override defaults off. Enabling it removes only the exact conflicting
  IP from the old user's automatic-login list; accounts and unrelated settings
  are retained. Group, MAC, template and non-exact rules fail closed.
- Desired state commits before remote mutation. Failed revocation remains
  pending, survives restart and retries. Capacity, concurrency, responses and
  retry frequency are bounded.
- Authentication is separate for events and administration. Management writes
  require origin and CSRF checks; GUI rendering does not interpret target names
  as HTML. New Kerio targets verify TLS by default.
- Literal deployment passwords survive Compose interpolation. Existing config
  is preserved. Container packaging uses a non-root account and restricted
  filesystem/capabilities; publication is configured to depend on CI tests.

Local verification: **60 Python tests passed on Python 3.13.3**; Node DOM/GUI
checks passed; Python compilation, Bash syntax and diff checks passed. The full
Compose configuration validated. The real entrypoint started on loopback and
answered its HTTP health endpoint. Additional tests inject initial/final state
write failures and deliver Stop during a delayed failing login
(`tests/test_regressions.py:79`, `:86`, `:102`).

## Remaining acceptance work and explicit limits

1. Run the [live acceptance matrix](operations.md) on the actual PacketFence,
   Kerio and NAS builds. Mocked contract tests cannot establish permissions,
   manual-rule persistence or resulting firewall traffic policy.
2. Run container build/runtime checks and Python 3.12 CI. The local Docker daemon
   was unavailable and only Python 3.13 was installed. CI was added, not executed
   remotely during this task.
3. Same-identity out-of-order events lack an upstream session sequence. The
   bridge trusts authenticated PacketFence events; it does not poll PacketFence
   per event. NAS roaming/Stop behavior requires acceptance testing.
4. Kerio provides no revision compare-and-swap for this Users.set operation.
   Independent administrative edits can still race; use the documented change
   procedure and configuration backups.
5. Upstream PacketFence TLS verification remains an upstream concern. Restrict
   the management path or use an authenticated tunnel as documented.
6. Shared-state replicas are unsupported. Existing environment-only single-target
   seeds must be migrated to persisted target configuration.

There are no deferred minor findings from the final review. These limits are
deployment/integration requirements, not evidence of production acceptance.
