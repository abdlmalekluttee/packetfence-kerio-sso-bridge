# PacketFence authority monitor

Fresh live inspection found 31 pending addresses absent from Kerio but still registered in PacketFence. Six old leases have ended IP records and newer addresses for the same devices. One old Kerio address still carries traffic. Registration expiry (often five days) does not describe current IP ownership.

Add an optional read-only PacketFence API client using a dedicated NODES_READ account. Batch refresh tracked IPv4 bindings and registered node identities every 60 seconds; cache observations, bound HTTP work and use outage backoff. Verify TLS normally or pin the certificate obtained through a trusted channel. Never write PacketFence records. Missing, ambiguous, malformed, truncated or unavailable source data must not authorize a Kerio mutation.

For a confirmed obsolete binding, suspend login/logout and manual-policy changes. Preserve any existing Kerio host, even idle; retire the bridge lease only after two successful source observations at least 60 seconds apart and a fresh Kerio read proves no host exists. Do not infer offline status from last_seen. Fresh trusted events reset retirement confirmation. Keep normal guarded Stop handling for confirmed current bindings. Ignore link-local, loopback, unspecified and multicast event addresses without creating desired state.

Correct current Kerio sessions remain no-ops. Pending absent hosts with current source ownership are waiting for device traffic, not a login failure; expose waiting, held and failure counts separately while retaining the legacy pending total. Do not change domains, library routing, or broad MAC/group override policy.

Deploy after tests, independent review and GitHub CI. Compare existing session identities and login times before/after; do not perform disruptive live test logouts.
