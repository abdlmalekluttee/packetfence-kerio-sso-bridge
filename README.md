# PacketFence → Kerio Control SSO Bridge

A small Python service translating authenticated PacketFence JSON-RPC SSO events
into Kerio Control identity mappings. Runs as UID 10001, with no third-party Python
runtime dependencies.

## Smart synchronization

| Observed state | Behavior |
| --- | --- |
| Kerio already has the expected user | No logout/login; refresh the durable lease |
| Repeated event within the verified cache window | No additional Kerio API call |
| Host is present without a user | Validate and log in the PacketFence user |
| Different active user | Freshly verify ownership, validate the new user, replace and verify |
| Conflicting manual automatic-login IP | Refuse by default; optional exact-IP removal |
| Host missing / API unavailable | Persist failure and retry with backoff |
| Stop / expiry | Revoke a matching owner unless a compatible active IP alias still needs the host |
| Different identities on aliases of one host | Refuse rebinding; report the conflicting leases |

POST `/` accepts Start and Stop, plus Update as an extension. HTTP Basic uses
BRIDGE_USER/BRIDGE_PASS. GET `/` is the management GUI using separate admin
credentials. PacketFence's generic event has no session sequence: see the ordering
limits in [operations](docs/operations.md).

## Optional manual-IP override

Each firewall has **Allow removal of conflicting manual IP assignments** (off by
default). When a different PacketFence user needs an IP currently automatically
assigned to someone else, enabling this permits a minimal Kerio Users.set update
removing that exact address from the previous user's automatic-login list.

The bridge preserves other addresses and account settings, verifies the write,
then verifies the active login. It never deletes users. Shared address groups,
MAC rules, inherited settings and non-exact address rules require manual resolution.
Disabling the option prevents future removals; it does not restore earlier ones.
Saving waits for any in-flight operation on that target. After a successful
disable response, an older policy cannot perform another removal.
The Kerio API account needs configuration-write permission for this feature.

## Install

Requirements: Linux host, Docker Engine, Docker Compose v2 supporting `up --wait`,
Python 3.12+ for the setup helper, OpenSSL, and access to Kerio's administration API.
Kerio must see each client's IP in Active Hosts and be in the traffic path for
its policies to apply. Users must exist in the intended Kerio directory.

```bash
git clone https://github.com/abdlmalekluttee/packetfence-kerio-sso-bridge.git
cd packetfence-kerio-sso-bridge
sudo ./deploy.sh
```

The script preserves an existing .env, prompts for new credentials only on first
setup, generates a self-signed certificate with an IP SAN if missing, restricts
permissions, builds locally and waits for HTTP health. For trusted browser TLS,
install a certificate from your CA. Restrict port 9090 to PacketFence and admins.
See [migration/rollback](docs/operations.md) before upgrading an existing install.

Manual configuration: use `python3 configure.py` to generate safely escaped dotenv
values. Spaces, dollar signs, quotes and backslashes are supported. Do not use
`source .env`; Compose dotenv syntax is not a shell script. Empty or old placeholder
passwords are rejected by the application. Never print real `docker compose config`
output in shared logs because it contains resolved secrets.

## PacketFence configuration

1. Select your supported IP discovery path: DHCP visibility/IP helpers, or RADIUS
   accounting containing Framed-IP-Address. Accounting is not universally required.
2. Enable the corresponding SSO trigger, separately from the IP-log update setting.
   For accounting, verify both SSO-on-accounting and acting on accounting Stop.
3. Add a JSONRPC firewall for the bridge host/port with BRIDGE_USER/BRIDGE_PASS.
   Select applicable roles and networks; an empty role selection may send nothing.
4. Preserve the full username realm. Use per-target default_domain only when bare
   usernames intentionally belong to that domain; do not strip domain distinctions.
5. Check PacketFence event caching and renewal intervals against registration
   timeouts and FALLBACK_TTL. Capture a real Start and Stop during acceptance.

Internal PacketFence Update logging does not guarantee an Update RPC on the wire.
The reviewed upstream JSONRPC client implements Start/Stop. The bridge accepts both
Start and Update as equivalent renewals. Configuration/version details and primary
API references are in [the specification](docs/superpowers/specs/reliable-sso.md).

## Configuration

| Variable | Default / behavior |
| --- | --- |
| BRIDGE_USER / BRIDGE_PASS | Required; PacketFence endpoint credentials |
| ADMIN_USER / ADMIN_PASS | Required; management credentials |
| LISTEN_ADDR / LISTEN_PORT | 0.0.0.0 / 9090 |
| BIND_ADDR / HOST_PORT | Compose publication: 0.0.0.0 / 9090 |
| CERT_FILE / KEY_FILE | Required for direct HTTPS; setup uses /certs/bridge.crt and bridge.key |
| ALLOW_HTTP | false; explicit private reverse-proxy mode only |
| PUBLIC_ORIGIN | External https://host[:port] when using a proxy; no trailing slash |
| CONFIG_PATH | /data/kerios.json, plaintext API credentials; mode 0600 |
| STATE_PATH | /data/state.sqlite3; durable leases/retries |
| VERIFIED_TTL | 30 seconds; repeated matching events skip Kerio reads |
| RECONCILE_INTERVAL | 60 seconds; periodic verification of active mappings |
| FALLBACK_TTL | 3600 seconds for missing/zero Start timeout |

Positive PacketFence timeouts set lease expiry directly. Failed operations remain
pending with 2..300-second retry backoff. State capacity is 10000 IPs; completed
revocations are retained for one hour then pruned. One service instance per state
directory; do not share the SQLite/JSON files between replicas.

Per target: host, port, API credentials, subnets, prefix/suffix, default_domain,
verify (on for new targets), ca_file (optional private CA inside the container),
enabled, override_manual (off). Existing explicitly insecure TLS settings are
preserved on upgrade; move them to verified certificates as part of migration.

## Monitoring and tests

The GUI shows active mappings and pending failures. Test checks session login and
ActiveHosts read permission; it does not prove every write permission. HTTP
`/healthz` detects service/worker failure, not every firewall outage. Monitor
`/api/status` with admin credentials for pending operations and journal logs for
`sync_pending` and `manual_ip_removed`.

```bash
python -m unittest discover -v
node tests/test_ui.js
```

Tests mock remote appliances and exercise real synchronization, persistence,
HTTP/TLS, and GUI logic. CI runs Python 3.12/3.13 and a non-root container smoke test
before publication. A real PacketFence/Kerio lab acceptance remains necessary;
no new appliance version compatibility is claimed from mocks alone.
See [review results](docs/review-results.md) for reproduced findings, fixes and
the limits of local verification.

## License

MIT. Built by Luttei; unofficial, not affiliated with PacketFence or GFI/Kerio.
