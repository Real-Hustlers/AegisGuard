# S7-B — Retention & SQLite Storage Security

S7-B extends S7-A with bounded failed-payload retention and SQLite
secure-deletion settings.

## Failed durable-ingest payload retention

Failed analyzer-side collector batches temporarily keep their payload so the
failure can be inspected and recovered. S7-B sets the default retention period
for that duplicate raw payload to 30 days.

On analyzer ingest-worker startup, failed batches older than the retention
window have `payload_json` replaced with `{}`. Operational metadata remains.

This does not delete canonical `security_logs`, incidents, evidence references,
or audit events.

## SQLite hardening

Analyzer and collector SQLite connections enable:

- `PRAGMA secure_delete = ON`
- `PRAGMA temp_store = MEMORY`

The collector already deletes acknowledged outbound batches. Secure deletion
hardens that existing path without changing checkpoint or retry semantics.

These controls are defense in depth, not encryption at rest. Deployment-level
disk encryption remains a separate control.

## Scope exclusions

S7-B does not change detection, ML, correlation, MITRE, incident semantics,
authentication, authorization, or response execution.

Legacy/manual raw JSON output remains for a later S7 slice.
