# S9.1 — Runtime Reliability

S9.1 establishes a concrete runtime-reliability contract for the AegisGuard
Enterprise/SIEM Analyzer without changing detection, incident, response, or
collector delivery semantics.

## Baseline audit

The merged S9 baseline already had:

- guarded writable runtime-path resolution;
- SQLite schema initialization and WAL/concurrency configuration;
- durable collector ingestion;
- an ingest worker stop event;
- worker join during direct Flask shutdown;
- worker stop/join plus `server_close()` during mTLS shutdown.

The audit did not find dedicated liveness/readiness HTTP endpoints or an
explicit startup dependency preflight.

S9.1 therefore adds those missing controls and preserves the existing graceful
shutdown behavior as a tested invariant.

## Liveness

```text
GET /healthz
```

Liveness only answers whether the Analyzer application process is serving
requests.

Response:

```json
{
  "service": "aegisguard-analyzer",
  "status": "ok"
}
```

The endpoint deliberately does not query SQLite or disclose filesystem,
configuration, certificate, user, collector, or security-event information.

## Readiness

```text
GET /readyz
```

Readiness verifies:

1. the Analyzer can open its canonical SQLite database;
2. SQLite `quick_check` reports `ok`;
3. the core schema tables exist;
4. the configured Analyzer data directory is writable.

Success returns HTTP 200 and `status=ready`.

Dependency failure returns HTTP 503 and `status=not_ready`.

Failure output uses stable non-sensitive reason codes such as:

```text
database_unavailable
data_directory_unavailable
```

Raw exception text, paths, credentials, and database contents are not exposed.

## Startup preflight

Both supported Analyzer launch paths perform the same readiness validation
before starting the durable ingest worker and before entering normal network
service:

- direct source Flask launcher;
- enterprise mTLS launcher.

If a required dependency is not ready, startup fails closed with a bounded
generic readiness error.

This prevents the Analyzer from presenting itself as operational while its
canonical persistence layer or writable runtime directory is unavailable.

## Graceful shutdown

S9.1 does not replace the existing shutdown mechanics.

Direct Flask shutdown retains:

```text
ingest_stop_event.set()
→ ingest_thread.join(timeout=5)
```

mTLS shutdown retains:

```text
ingest_stop_event.set()
→ ingest_thread.join(timeout=5)
→ server.server_close()
```

The S9.1 closure test protects these sequences against accidental removal.

## Security boundary

`/healthz` and `/readyz` are deliberately outside `/api/`.

They expose only minimal operational state and no human application data. They
are therefore suitable for local service supervisors and deployment health
checks without requiring a browser session.

No response policy, authorization policy, collector trust, privacy projection,
or audit-evidence semantics are changed.

## No schema migration

S9.1 introduces no database migration.

## Scope intentionally unchanged

S9.1 does not change:

- collector authentication or mTLS verification;
- durable batch ACK/retry behavior;
- event parsing/classification;
- ML scoring;
- correlation or MITRE mapping;
- incident lifecycle;
- S8 response governance;
- S7 privacy controls;
- S10 packaging/service ownership.

## Validation gate

S9.1 is complete when:

- focused S9.1 tests pass;
- platform/intelligence/frontend/deployment/collector/analyzer regressions pass;
- `git diff --check` is clean;
- the change is merged into `product/integration`.
