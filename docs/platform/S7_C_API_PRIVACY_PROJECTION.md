# S7-C — Role-Aware API Privacy Projection

S7-C adds a read-side privacy boundary for human SOC APIs.

## Policy

- `ADMINISTRATOR` and `ANALYST` retain the full security telemetry required for
  investigation and operations.
- `VIEWER` retains status, severity, timestamps, counts, IDs, ML outcomes, and
  other non-sensitive context, while security-sensitive identifiers and raw
  evidence fields are redacted.
- Secret-bearing fields are redacted for every role.

## Protected read surfaces

The projection applies to GET/HEAD responses under:

- `/api/events`
- `/api/alerts`
- `/api/devices`
- `/api/incidents`
- `/api/response-actions`
- `/api/soar`

Authentication and collector/device APIs are not modified by this layer.

## Storage semantics

S7-C is presentation-only. It does not alter or delete:

- `security_logs`
- incident records
- audit events
- evidence references
- collector payload state
- ML/detection/correlation data

Canonical evidence remains available to roles that require it.

## Scope boundaries

This slice does not modify authorization rules, detection, ML, correlation,
MITRE mapping, incident lifecycle rules, collector authentication, or response
execution.
