# S7-A — Data Security & Privacy Foundation

S7-A introduces the first enterprise data-minimization controls after the S6
Unified Incident Platform.

## Scope

This slice is intentionally additive and does not change detection, ML,
correlation, MITRE mapping, incident-candidate semantics, or response
execution.

### 1. Data classification contract

`backend/platform/data_privacy.py` defines four coarse classifications:

- `PUBLIC`
- `INTERNAL`
- `SECURITY_SENSITIVE`
- `SECRET`

Credentials and authentication secrets are always redacted by the shared
mapping/text utilities. Security telemetry remains available to SOC workflows
unless a caller explicitly requests lower-trust redaction.

### 2. Durable ingest data minimization

Collector batches must contain the complete payload while they are queued or
processing so the durable worker can recover after interruption.

After a batch reaches `PROCESSED`, S7-A replaces `payload_json` with `{}`.
The queue retains the batch identity, collector identity, hostname, event
count, record checkpoint, timestamps, attempt count, and final state, but no
longer keeps a second copy of the event bodies.

The canonical `security_logs` records are not changed by this slice.

Failed batches retain their payload so operators can recover/retry the batch,
but persisted failure text is passed through secret redaction first.

### 3. External ingest error minimization

The legacy upload API no longer returns `str(exception)` to the client on an
internal analyzer failure. A sanitized diagnostic remains available in the
server console.

## Existing controls preserved

S7-A builds on, rather than replaces:

- application authentication/RBAC and CSRF controls;
- collector authentication/mTLS boundaries;
- Windows DPAPI protection for collector credentials;
- S5 audit-detail secret redaction and integrity chain;
- API `Cache-Control: no-store`;
- S6 incident references instead of copied raw evidence bodies.

## Next slices

Later S7 work should cover retention policy enforcement, database/file
permissions, configuration-secret validation, governed exports, backup
confidentiality, and API-specific privacy projections.
