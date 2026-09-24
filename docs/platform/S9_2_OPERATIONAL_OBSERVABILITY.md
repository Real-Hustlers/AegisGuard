# S9.2 — Operational Observability

S9.2 adds bounded operational visibility to the AegisGuard Enterprise/SIEM
Analyzer while preserving the existing audit, privacy, collector-trust, and
response-governance boundaries.

## Baseline audit

The merged baseline already provides:

- server-generated request correlation IDs;
- tamper-evident sensitive-operation audit records;
- administrator-only audit read/integrity endpoints;
- S7 secret-redaction helpers;
- secret-safe Collector diagnostics;
- S9.1 liveness, readiness, startup preflight, and graceful shutdown.

The baseline did not provide:

- a structured operational request-event stream;
- bounded aggregate request metrics;
- an administrator-governed operational diagnostics surface.

## Structured operational events

S9.2 emits compact JSON events for request completion.

Example shape:

```json
{
  "correlation_id": "req-...",
  "duration_ms": 4.2,
  "endpoint": "dashboard",
  "event_name": "http.request.completed",
  "method": "GET",
  "outcome": "success",
  "service": "aegisguard-analyzer",
  "status_code": 200,
  "timestamp": "..."
}
```

The operational log uses an explicit allow-list. It does not accept or emit:

- request bodies;
- query strings;
- raw URL paths containing dynamic identifiers;
- peer/source/destination IP addresses;
- usernames or session identifiers;
- hostnames;
- raw security events;
- credentials, cookies, CSRF values, or tokens.

The server-generated correlation ID links operational events to the existing
audit trail without trusting a caller-supplied correlation identity.

## Bounded metrics

S9.2 records process-local aggregate metrics only:

- uptime;
- total requests;
- total completed responses;
- current in-flight requests;
- response counts by coarse HTTP class;
- average response latency;
- maximum response latency.

Metrics contain no endpoint labels, user labels, host labels, IP labels, or
other high-cardinality security data.

Metrics intentionally reset when the Analyzer process restarts. Persistent
historical telemetry is outside this slice.

## Administrator-only visibility

S9.2 adds:

```text
GET /api/operations/metrics
GET /api/operations/diagnostics
```

Both are administrator-only through the existing application RBAC policy.

The diagnostics response contains only:

- service identity;
- source/frozen runtime mode;
- S9.1 readiness state;
- bounded aggregate metrics.

It does not expose filesystem paths, database contents, certificate material,
credentials, environment variables, request data, or security-event content.

A readiness-provider failure is converted to the stable reason:

```text
readiness_probe_failed
```

Raw exception text is not returned.

## Audit boundary

S9.2 does not replace or weaken the security audit trail.

Use the audit subsystem for:

- actor identity;
- sensitive action history;
- authorization denials;
- response approvals/rejections/retries/reconciliation;
- integrity verification.

Use S9.2 operational observability for:

- request completion;
- service health trends;
- HTTP failure-rate visibility;
- latency and in-flight load.

Correlation IDs provide the linkage between these two layers.

## No schema migration

S9.2 introduces no database migration.

## Scope intentionally unchanged

S9.2 does not change:

- event ingestion semantics;
- Collector authentication or mTLS;
- durable queue/ACK behavior;
- ML/classification/correlation;
- incident lifecycle;
- S7 privacy projection;
- S8 response governance;
- S9.1 readiness/startup/shutdown behavior;
- S10 packaging/service ownership.

## Validation gate

S9.2 is complete when:

- focused S9.2 tests pass;
- platform/intelligence/frontend/deployment/collector/analyzer regressions pass;
- `git diff --check` is clean;
- the change is merged into `product/integration`.
