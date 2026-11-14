# Reliable PacketFence / Kerio synchronization

## Intent
Make repeat PacketFence events cheap and idempotent. Match the authenticated
PacketFence event's formatted username against Kerio before any mutation. A
matching binding causes no logout/login. A differing active user is replaced
only after a fresh read and target-user validation. Add a per-firewall option
`override_manual` (default false) for removing an exact conflicting persistent
automatic-login IP from the previous user's Kerio configuration.

## Contracts
- Python >=3.12, standard-library runtime, Docker non-root UID 10001.
- PacketFence POST / uses HTTPS + Basic and returns result ["OK"] only for
  completed or safely ignored operations; outstanding failures return a message.
- Keep Start/Stop and accept Update as an extension. Event payload, not a new
  PacketFence API poll per event, is authoritative. Require user and IP for Stop.
- Canonicalize IPs and compare full usernames without dropping domains. Configure
  `default_domain` explicitly to reconcile a bare username with a domain user.
- Matching events refresh durable lease metadata; cache positive verification for
  30 seconds, share active-host snapshots for 2 seconds, reconcile every 60 seconds.
- SQLite stores desired state, generation, selected target, expiry and retry
  status. One record per IP, bounded at 10000. No unlimited in-memory task queue.
- Serialize each IP operation; acknowledge Stop only after its generation is
  reconciled. Retry failures with bounded exponential backoff (2..300 seconds).
- A positive PacketFence timeout expires the lease; missing/zero Start timeout
  uses a configurable 3600-second fallback. Stop timeout zero is not a lease.
- Ignore Stop for a different known user/MAC; never broadcast logout to all
  firewalls. Unknown Stop may revoke only a freshly verified matching user.
- Same-identity out-of-order sessions cannot be fully distinguished by the
  generic PacketFence payload (no session sequence). Document this limitation.
- Refuse ambiguous multi-firewall matches. No automatic cross-site guessing.
- Disabling persistent override must prevent Users.set; default remains off on
  migration. An automatic-login conflict while disabled returns a clear error.
- Override may remove only the exact IP from that user's enabled addresses list;
  preserve other IPs, MACs and groups, account, password, permissions and quota.
  Never delete users or edit shared address groups/ranges. Refuse unsafe automatic
  group/MAC cases. Domain-template User.data is separate from per-user autoLogin;
  preserve template settings while removing an exact personal IP. Verify saved
  configuration and final active identity.
- Use read-before-write, minimal Users.set, check result.errors, audit changes.
  No claim of atomic compare-and-swap: Kerio exposes no revision guard here.
- TLS verification defaults on with private CA support. Reject default/empty
  credentials at startup; plaintext requires explicit opt-in for a private proxy.
- Bounded HTTP concurrency, TLS handshake/read deadlines, body limits, strict
  schema validation; no public privileged mutation routes.
- GUI uses safe DOM creation and CSRF protection. Show policy toggle, status,
  pending/error counts. No credentials in responses or logs.
- Atomic validated target configuration; restrictive secret/state permissions.
- CI tests before publish; deployment preserves literal passwords and existing
  settings. Include migration, rollback, monitoring, and live acceptance guidance.
- Do not push, publish, deploy, or modify a real firewall during this task.

## API research (2026-11-14)
Primary sources, with narrow interpretations rather than SDK assumptions:
- [PacketFence JSONRPC implementation](https://github.com/inverse-inc/packetfence/blob/3d08e22d8caa4dc1c3eedf028d3510f0265413f9/go/firewallsso/jsonrpc.go): Start/Stop, named fields, non-OK result means failure.
- [PacketFence filters](https://github.com/inverse-inc/packetfence/blob/3d08e22d8caa4dc1c3eedf028d3510f0265413f9/go/firewallsso/base.go): role/network and separate accounting/DHCP/Stop gates.
- [PacketFence integration](https://www.packetfence.org/doc/PacketFence_Installation_Guide): DHCP and accounting paths; caching affects event frequency.
- [Kerio ActiveHosts](https://manuals.gfi.com/en/kerio/api/control/reference/interfacewebadmin_1_1_active_hosts.html): host-scoped login/logout; empty logout IDs means all (prohibited).
- [Kerio ActiveHost](https://manuals.gfi.com/en/kerio/api/control/reference/structwebadmin_1_1_active_host.html): user reference, authentication method and IPv6 aliases.
- [Users IDL](https://manuals.gfi.com/en/kerio/api/control/reference/_users_8idl_source.html): autoLogin.addresses and minimal-field Users.set; inspect per-item errors.
- [OptionalStringList](https://manuals.gfi.com/en/kerio/api/control/reference/structwebadmin_1_1_optional_string_list.html): enabled/value structure (IP list alias).
- [Domains](https://manuals.gfi.com/en/kerio/api/control/reference/interfacewebadmin_1_1_domains.html): domain enumeration; local ID is local.
- [Session](https://manuals.gfi.com/en/kerio/api/control/reference/interfacewebadmin_1_1_session.html): cookie plus X-Token, reauthentication on -32001.

Direct documented JSON-RPC avoids adding an SDK dependency for this small subset.
Mock contract tests cannot certify particular appliance versions: exact builds,
rights, manual-IP persistence and real traffic policy require lab acceptance.
