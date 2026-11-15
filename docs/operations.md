# Operations and acceptance

## Trust and authority

The bridge trusts events authenticated with BRIDGE credentials. This is identity
assertion, not independent user authentication or PacketFence-role replication.
Do not expose the listener publicly. Keep PacketFence, bridge, and Kerio on a
restricted management network; the reviewed PacketFence upstream HTTP client
itself disables certificate verification. A trusted bridge certificate alone
does not repair that upstream behavior. Use network isolation or authenticated
tunnels where transport authenticity cannot otherwise be enforced.

Kerio verification is on for new targets. Mount a private CA in /certs and set
ca_file rather than disabling verification. GUI credentials are separate from
event credentials. CSRF tokens and same-origin checks protect GUI writes.
Behind a proxy, set PUBLIC_ORIGIN exactly to the external HTTPS origin and bind
the plaintext backend to an isolated interface. Do not trust forwarded-origin
headers. Browser and API clients must send the origin and CSRF token for writes.

The manual-IP override grants a significant configuration capability. Use a
dedicated Kerio API account and validate its permissions. Broad group/MAC
rules intentionally fail closed. Kerio offers no atomic revision guard for this
Users.set operation: avoid concurrent administrative edits to the same user's
automatic-login list. The bridge rereads before writing and verifies afterward.
It does not restore removed manual assignments on Stop or when the toggle is off.
Policy saves serialize with in-flight target operations. A successful disable
response means all operations using the old policy have finished; if the target
is busy, the save can fail and must be retried. It does not cancel a removal that
has already reached Kerio.

Kerio's Users.get warning 8003 reports short-name collisions between local and
domain accounts. The bridge permits this documented read warning while still
requiring an exact full-domain identity and a unique user in that domain. It
does not convert, rename, or delete local accounts. Authentication warning 8004,
unknown warnings, and warnings or item errors on configuration writes remain
blocking failures. This behavior was checked against Kerio 9.3.4 build 3795.

Domain templates control User.data (rights, quotas, web filtering, and language);
User.autoLogin is a separate per-user field in the
[Kerio Users API source](https://manuals.gfi.com/en/kerio/api/control/reference/_users_8idl_source.html).
Exact-IP removal therefore also supports users with useTemplate enabled. The
write includes only autoLogin: it never disables the template or writes its
rights/quotas. Enabled MAC or address-group automatic-login rules still block
automatic removal, and concurrent template-setting changes abort the write.

## Domain routing and short realms

Each Kerio target has a `domains` list, intersected with its `subnets` list.
For example, one firewall can serve `["hiss.local", "tanasuh.local"]` and another
`["library.local"]`. An empty domains list accepts any domain for backward
compatibility. `local` selects unqualified users when no default domain or suffix
is configured. Avoid overlapping domain/subnet scopes across firewalls.

Configure explicit `domain_aliases`, for example
`{"hiss":"hiss.local", "tanasuh":"tanasuh.local"}`. Then `lab@hiss`,
`HISS\lab`, and `lab@hiss.local` identify the same account. Aliases are resolved
before domain routing, user lookup, session comparison and login. No suffix is
guessed and unrelated domains remain distinct. Correct existing sessions and
cached renewals require no login/logout writes or extra directory queries.

If every configured target excludes a domain, its events are acknowledged
without contacting Kerio. Existing leases for that excluded domain are retired
as ignored during reconciliation, without logging users out. This deliberately
stops managing them, including future expiry logout. A disabled target still
owns its domains: its events remain pending instead of being discarded. With no
targets configured, events remain pending. Configure **every** target's domain
scope explicitly to exclude a domain; a target with an empty list accepts all.

Domain and alias edits use the active-lease guard. Existing leases stay pinned to
their target ID and cannot automatically transfer between firewalls. Drain or
plan a controlled migration before changing an active target's identity policy.
An excluded lease already completed as ignored releases its old target when a
new managed event arrives, so a subsequently added domain target can handle it.
Domains do not make overlapping tenant IP spaces safe: state is still keyed by
IP. Use separate bridge instances for overlapping tenant networks.

## Reconnect timing

Start and Update are presence hints, not reliable new-session markers. When an
active lease is pending because its host is missing, either event can shorten
the old retry timer. A durable five-second per-IP cooldown limits duplicate
events; a ten-second window permits worker follow-ups if Kerio sees traffic just
after the event. Without more events the normal exponential backoff resumes.
The host list remains shared and cached for two seconds per Kerio target, so a
burst of missing IPs can reuse one snapshot. Pagination and login verification
can require additional reads when hosts actually need binding.

The worker also checks a shared snapshot every five seconds for each target with
pending missing-host leases. This discovers a device that begins sending traffic
after the event window ends, without waiting for another event or the old retry.
Only visible IPs are woken; absent leases keep their existing retry deadlines.
There is no such discovery scan when no missing-host leases need it. A snapshot
may span several API pages; each detected arrival still passes normal ownership,
ambiguity, expiry and MAC checks before any write. API failure backoff remains in
force. These are scheduled intervals, not a hard latency guarantee under load.

This does not bypass API outage backoff, manual-rule restrictions, username/MAC
checks or Stop protections. It does not poll PacketFence for online status.
PacketFence must deliver an event and Kerio must see the device; no strict
end-to-end login deadline is guaranteed. A correct Kerio session is preserved,
including portal logins. Old persisted leases work without a schema migration.

## Migration

1. Schedule a maintenance window. Record exact PacketFence/Kerio versions and
   export the relevant Kerio configuration, especially automatic-login addresses.
2. Stop the old bridge, then back up .env, certs/ and data/ with restrictive modes.
   For subsequent upgrades stop this bridge before filesystem-copying SQLite;
   include state.sqlite3 plus any WAL/SHM files, or use sqlite3's backup facility.
3. Preserve existing .env and kerios.json. New code validates old target entries
   and supplies missing policy fields without enabling override. Existing false
   verify settings remain false; migrate them to trusted TLS deliberately.
4. Replace placeholder credentials before startup. Earlier unescaped dollar
   passwords may already have been altered by Compose; regenerate credentials
   with configure.py after securely moving the old .env to a backup. Update PF.
5. Run deploy.sh. Its success means HTTP health, not appliance acceptance.
6. Open the GUI, set explicit subnets and full/default domain mapping, configure
   trusted TLS and run Test. Enable manual override only on the intended targets.
7. Run the matrix below. Monitor pending failures before returning to service.

The old KERIO_HOST single-target environment seed is retired; migrate targets via
the GUI or retain their existing JSON. RETRY_TRIES/RETRY_DELAY are replaced by
durable exponential retries. Unknown-target Stop now requires a username and
checks the current owner; it never broadcasts logout across all firewalls.

## Timing and ordering

The verified cache can hide external changes for up to VERIFIED_TTL seconds on
incoming renewals; the periodic sweep catches drift on its next successful pass.
Polling is best effort under API latency/outage and must not be interpreted as a
hard revocation deadline. Never use this bridge as the sole time-critical access
control mechanism. Lease expiry survives restart, but remote revocation cannot
complete while Kerio is unreachable; pending status remains visible.
Nonmutating reconciliation shares an indexed, two-second Active Hosts snapshot
across leases. Logout and conflicting-identity changes still use fresh reads.

Generic PacketFence events contain user/MAC/IP/role/timeout but no session sequence.
Different-owner Stop events are ignored. A stale Stop for the *same* identity
after a newer session, or a stale Start delivered after Stop, cannot always be
distinguished. Configure the upstream to emit suitable disconnect events and
validate your NAS's roaming/accounting behavior. Do not enable a blanket Stop
delay that silently extends access. Full session-order guarantees require an
upstream session identifier/sequence or authoritative session lookup extension.

A changed device IP gets its own lease; the old lease is revoked by its matching
Stop or expiry. Do not prematurely log out other IPs belonging to the same user.
Kerio operations affect a host ID, including its IPv4/IPv6 aliases. A Stop or
expiry preserves that host while another compatible alias lease is active.
Conflicting desired identities on aliases fail without rebinding; resolve the
PacketFence lease conflict instead of allowing repeated host-wide replacement.
NAT/shared-IP and overlapping tenant networks need separate bridge instances or
unambiguous routing; IP-only generic events cannot identify a tenant.

## Configuration changes

Targets with active/pending leases cannot be deleted through the GUI. Disabling
a target pauses its synchronization and reports pending failure rather than
revoking arbitrary hosts. Restore the target to complete revocation. Do not
change target host/subnets/domain settings during active sessions without a
controlled drain: the management API rejects these changes while leases exist.
Existing leases are pinned to the selected target ID. Direct edits to JSON bypass
this API guard and must only be performed during a controlled maintenance window.

Plaintext API passwords, lease user/IP metadata, and backups are sensitive. Data
directories use 0700 and files 0600; Windows uses filesystem ACLs instead of POSIX
mode enforcement. Never share a data directory across running instances. Preserve
logs for manual-IP audits; the event records target/user ID/IP without passwords.

## Live acceptance matrix (not performed by the implementation agent)

| Scenario | Required observation |
| --- | --- |
| Correct user already logged in | Zero ActiveHosts.logout/login calls |
| 100 identical renewals inside 30s | No additional Kerio requests after verification |
| Roam with same IP/user | No auth churn; inspect whether NAS also emits Stop |
| Different user obtains IP | Correct full-domain user bound after verification |
| Exact manual IP conflict, override off | No Users.set/logout; visible pending conflict |
| Exact manual IP conflict, override on | Only that address removed, other settings unchanged; correct user active |
| Group/MAC auto-login | No configuration write; clear manual-resolution error |
| Exact IP on a domain-template user | Remove only the personal IP; template flag and rights/quotas unchanged |
| Same username, different domains | Never treated as equivalent |
| Stop while login is in flight | Stop reconciles latest desired state; no final stale login |
| Kerio down during Stop | Non-OK reply, pending state; revocation after recovery |
| Bridge restart after lease expiry | Matching stale mapping revoked |
| Invalid/untrusted Kerio certificate | Connection refused with verify enabled |
| Silent TCP peer on HTTPS port | Other clients continue receiving responses |
| IPv6 aliases | Lookup matches canonical alias on the tested appliance |
| One alias stops while another is active | No host logout until the last compatible lease ends |
| Different identities on one host's aliases | Visible conflict; no repeated rebinding |
| Override disabled during an operation | No old-policy removal after successful save response |
| Container restart/disk-full | No false success or silently empty configuration |

Record appliance build, PacketFence build, NAS model, accounting interval,
SSO cache settings, API permissions, request counts, and resulting traffic policy.
Manual assignment support is based on the documented exact-address Users API;
validate persistence/readback on your specific appliance before enabling it.

## Rollback

Stop the new container. Restore the previous code/image and preserved config.
Keep the new state database for investigation; the old application does not use
it. Review manual_ip_removed audit events and restore intended exact IP entries
from the Kerio export if needed; toggling the feature off does not undo changes.
Reconcile any active mappings explicitly with PacketFence before normal service.

## Release maintenance

Use immutable commit image tags for rollback. Review/update the python:3.12-alpine
base regularly, rebuild for OS/Python security updates, scan images before
production rollout, and pin approved image digests in deployment infrastructure.
The repository CI tests code but does not establish that a particular built image
has no vulnerabilities. Test credentials and PEM keys under tests/fixtures are
public loopback fixtures and are excluded from Docker build context.
# Optional PacketFence authority monitor

Set `PACKETFENCE_CONFIG=/data/packetfence.json` to enable independent, read-only checks of tracked IPv4 ownership. Without it the bridge keeps its existing event/expiry behavior. Protect this file with mode `0600`, owned by the container UID (10001):

```json
{
  "host": "pf.example.test",
  "port": 9999,
  "username": "bridge-sso-observer",
  "password": "REPLACE_WITH_RANDOM_SERVICE_PASSWORD",
  "timezone": "Africa/Tripoli",
  "ca_file": "/certs/packetfence-ca.crt"
}
```

Use a dedicated local PacketFence account assigned an admin role containing **only `NODES_READ`**. The observer calls `POST /api/v1/login`, `POST /api/v1/ip4logs/search`, and `POST /api/v1/nodes/search`. Search POSTs are reads in PacketFence's authorization model. It never changes nodes, registrations, IP records, switch configuration or authentication sources. Set the timezone to PacketFence's timezone because IP log dates have no UTC offset. Docker includes timezone data; other installations need system timezone data (or Python's `tzdata` package).

TLS certificate/hostname validation is on by default; `ca_file` is optional for a public CA. For a legacy certificate, `certificate_sha256` can instead pin the SHA-256 of its DER certificate. Obtain the fingerprint through trusted console/SSH access. The pin is checked **before credentials are sent**. A changed certificate blocks source checks until an operator verifies and updates the pin.

The observer batches up to 100 tracked IPs per refresh and caches each successful observation for 60 seconds. With fewer than 100 stable mappings this normally needs two search requests per minute, plus authentication when required. New uncached mappings can require a pair of immediate read requests. A shared budget permits at most one batch per second, including event-triggered checks; deferred events wake when the next observation is available. Larger sets are processed in bounded batches. Each HTTP operation has an eight-second caller deadline and at most one outstanding network operation, including stalled DNS/connect work. Outages use 30–300 second backoff; missing, duplicate, malformed or truncated results are treated as unknown, never as evidence that a user left.

An obsolete binding is held: **no login, logout, or manual-IP edits**. Any visible Kerio host is preserved, even when idle. After two obsolete observations at least 60 seconds apart, a fresh Kerio read that finds no host allows automatic retirement of that old bridge mapping. A new PacketFence event resets confirmation. This prevents obsolete desired state from recreating a login later. A currently correct session remains untouched. Normal guarded Stop/expiry processing continues only when source ownership is confirmed.

The dashboard separates `waiting` (host absent), `held` (source obsolete/unknown), and `failed` (other reconciliation errors); `pending` remains their total for API compatibility. Waiting is not proof the device is offline: the device may not yet have sent traffic through this Kerio. Held mappings with visible hosts need monitoring, not forced logout. Source API errors appear separately. IPv6 source verification is not implemented: when this observer is enabled, IPv6 mappings are held as unverified. Link-local, loopback, multicast and unspecified event addresses are ignored without contacting Kerio.

PacketFence references: [API specification](https://packetfence.org/doc/api/) and [source controller](https://github.com/inverse-inc/packetfence/blob/stable/lib/pf/UnifiedApi/Controller/Ip4logs.pm). API shapes and NODES_READ permissions were also checked against the installed PacketFence 15.0 source. Observer provisioning is optional; it does not require enabling PacketFence's remote connector or accounting-stop events.

