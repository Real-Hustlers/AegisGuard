# S3-4B — Persistent Collector Security and Operational Health

S3-4B persists heartbeat health without allowing a collector to assert trusted
security state about itself.

## Trust separation

### Server-observed trust facts

Only the Analyzer writes:

- `last_heartbeat_at`
- `heartbeat_peer_ip`
- `heartbeat_credential_authenticated`
- `heartbeat_mtls_required`
- `heartbeat_mtls_verified`
- `heartbeat_certificate_fingerprint`

These come from successful server-side authentication, server mTLS policy, the
verified TLS peer certificate, and the observed peer address.

### Collector-reported operational state

The collector may report only a sanitized operational subset:

- `HEALTHY`, `BACKLOG`, `RETRY_WAIT`, or `DEGRADED`
- pending durable batch count
- ACK checkpoint
- durable collection cursor
- retry delay
- last successful ACK timestamp
- local certificate-rotation-pending flag
- collector version

Security-looking client fields are ignored and never promoted to trusted
server state.

## Schema

Platform schema v7 adds heartbeat/security-health columns to the existing
`collectors` table. The migration is additive.

## Runtime

`DurableCollectorRuntime.heartbeat()` derives its report from the existing
durable transport-health snapshot and sends only the approved operational
subset. Local analyzer URLs, local authentication configuration, and transport
error text are not included.

## Isolation

Heartbeat persistence remains separate from `collector_ingest_batches`.
Heartbeat does not enqueue logs or run detection, ML, correlation, or incident
processing.

## Next gate

S3-4C wires heartbeat cadence into the live collector and performs final S3
collector/device-security E2E closure.
