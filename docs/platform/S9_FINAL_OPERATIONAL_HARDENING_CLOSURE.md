# S9 — Final Operational Hardening Closure

This document closes the AegisGuard Enterprise/SIEM S9 workstream.

S9's authoritative product contract remains **Asset & Collector Management**:
read-only enterprise visibility over existing collector and asset platform
state without introducing a second collector trust model.

The later S9.1–S9.6 work adds runtime-hardening and validation evidence around
that contract. This closure distinguishes production controls from lightweight
validation foundations so the repository does not claim more than the
implemented code supports.

## Authoritative S9 contract

Production S9 asset/collector management is implemented through:

- `backend/analyzer/asset_api.py`
- `backend/storage/collector_inventory.py`
- `tests/platform/test_s9_collector_inventory.py`
- `docs/platform/S9_ASSET_COLLECTOR_MANAGEMENT.md`

It exposes only:

```text
GET /api/collectors
GET /api/collectors/<collector_id>
```

No S9 collector mutation endpoint is introduced.

## Authority separation

Server-authoritative state remains distinct from Collector-reported
operational telemetry.

Server-derived state includes collector identity, enrollment/revocation,
credential state, certificate state, server-observed contact, heartbeat,
mTLS state, durable queue state, and linked assets.

Collector-reported telemetry remains operational-only and is not promoted into
security trust.

Stored credential/certificate fingerprints and credential material are not
released by the S9 management API.

## Liveness semantics

Collector liveness is server-derived and uses:

```text
CURRENT
STALE
NEVER_SEEN
REVOKED
```

`REVOKED` takes precedence over recent activity.

The default stale threshold is 90 seconds and is configurable through:

```text
AEGISGUARD_COLLECTOR_STALE_AFTER_SECONDS
```

The threshold must be positive and is not an availability SLA.

## S9.1 — Runtime Reliability

S9.1 adds:

- `/healthz` liveness;
- `/readyz` dependency-backed readiness;
- SQLite and writable-data-directory startup preflight;
- fail-closed startup when required dependencies are not ready;
- preservation of graceful ingest-worker shutdown;
- preservation of mTLS `server_close()` shutdown.

## S9.2 — Operational Observability

S9.2 adds:

- allow-listed structured request-completion events;
- server-generated correlation-ID linkage;
- bounded process-local request metrics;
- administrator-only `/api/operations/metrics`;
- administrator-only `/api/operations/diagnostics`;
- generic readiness failure reporting without raw exception disclosure.

The operational stream intentionally excludes request bodies, query strings,
raw dynamic paths, IP/user labels, raw security events, credentials, cookies,
CSRF values, and tokens.

## S9.3–S9.6 supplemental validation foundations

The merged tree also contains lightweight helper/validation artifacts:

```text
S9_3_HEALTH_MONITORING.md
health_monitoring.py
test_health_monitoring.py

S9_4_PRODUCTION_READINESS.md
production_readiness.py
test_production_readiness.py

S9_5_RESILIENCE_RECOVERY.md
resilience_recovery.py
test_resilience_recovery.py

S9_6_SECURITY_VALIDATION.md
security_validation.py
test_security_validation.py
```

These are supplemental foundations. They do not replace the production S9
collector-management, S9.1 reliability, or S9.2 observability controls, and
this closure does not represent them as full service orchestration, disaster
recovery, or remote remediation engines.

## No new trust or execution surface

The final S9 closure introduces no:

- collector mutation API;
- remote Collector command execution;
- generic host command execution;
- new response execution path;
- new credential/certificate trust model;
- new human authorization model;
- database schema migration.

S8 response governance and S10 deployment ownership remain unchanged.

## Final closure invariants

S9 is technically closed when:

1. collector inventory remains read-only;
2. server trust state stays separate from Collector-reported telemetry;
3. sensitive credential/certificate material is not exposed by inventory;
4. liveness remains server-derived;
5. S9.1 health/readiness/startup controls remain present;
6. S9.2 metrics/diagnostics remain bounded and administrator-only;
7. S9.3–S9.6 remain represented as supplementary validation foundations;
8. focused S9 closure tests and the full regression gate pass;
9. `git diff --check` is clean;
10. this closure is merged into `product/integration`.

## Closure validation gate

```text
python -m pytest tests/platform/test_s9_final_closure.py -q
python -m pytest tests/platform/test_s9_collector_inventory.py -q
python -m pytest tests/platform/test_s9_1_runtime_reliability.py -q
python -m pytest tests/platform/test_s9_2_operational_observability.py -q
python -m pytest tests/platform -q
python -m pytest tests/intelligence -q
python -m pytest tests/frontend -q
python -m pytest tests/deployment/test_s10_windows_deployment_contract.py -q
python -m pytest backend/collector/test_live_monitoring.py -q
python -m pytest backend/analyzer/test -q
git diff --check
```

After this closure merges, further operational capabilities should start under
a separately named roadmap scope instead of silently extending S9.
