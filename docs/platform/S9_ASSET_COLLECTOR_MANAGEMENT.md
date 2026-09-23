# S9 — Asset & Collector Management

## Purpose

S9 provides read-only enterprise visibility over the existing AegisGuard
collector and asset platform state.

It does not create a second collector trust model.

## Authority boundaries

### Server-authoritative

The following are derived from Analyzer/platform state:

- collector identity
- registered hostname
- enrollment/revocation status
- credential state
- certificate state
- certificate-rotation state
- last authenticated activity
- heartbeat time
- server-observed peer IP
- whether the credential was authenticated
- whether mTLS was required
- whether mTLS was verified
- durable server queue state
- linked asset records

Stored credential and certificate fingerprints are intentionally not exposed
through the S9 management API.

### Collector-reported operational telemetry

The following are displayed separately and are not promoted into security
trust:

- collector version
- transport status
- pending batches
- ACK checkpoint
- collection cursor
- retry delay
- last successful ACK
- locally reported certificate-rotation pending state

## Liveness states

S9 derives liveness only from server-observed contact timestamps.

States:

- `CURRENT` — latest authenticated activity or heartbeat is within the
  configured stale threshold.
- `STALE` — a server-observed contact exists but is older than the threshold.
- `NEVER_SEEN` — the collector is registered but no server-observed contact
  timestamp exists.
- `REVOKED` — the server identity is revoked. This takes precedence over
  recent contact.

The built-in collector heartbeat interval defaults to 30 seconds.

S9 therefore defaults the presentation stale threshold to 90 seconds,
equivalent to three missed default heartbeat intervals.

This threshold is an operational presentation setting, not an availability
SLA or product performance guarantee.

Configure it with:

`AEGISGUARD_COLLECTOR_STALE_AFTER_SECONDS`

The value must be greater than zero.

## API

Read-only endpoints:

- `GET /api/collectors`
- `GET /api/collectors/<collector_id>`

These are normal human application APIs and are therefore covered by the
existing AegisGuard application-session RBAC policy.

No S9 collector mutation endpoints are introduced.

## Security boundary

S9 does not modify:

- collector authentication
- enrollment
- credential generation
- credential rotation/recovery
- mTLS validation
- certificate binding/rotation
- human RBAC
- audit-chain integrity
- incident lifecycle
- response execution

The existing Saran-owned platform remains authoritative for those functions.
