# S3-4A — Authenticated Collector Heartbeat

S3-4A adds a narrow authenticated liveness path for enrolled collectors.

## Endpoint

```text
POST /api/collector/v1/heartbeat
```

The request carries:

- `X-AegisGuard-Collector-ID`
- `X-AegisGuard-Collector-Credential`
- JSON `collector_id`
- JSON `hostname`
- optional JSON `version`

## Security boundary

Heartbeat authentication reuses the authoritative S3 collector identity
registry.

A heartbeat is accepted only after:

1. collector ID/header-body binding succeeds;
2. a bearer device credential is present;
3. when mTLS is required, the verified TLS peer certificate is bound to the
   same collector;
4. the collector is not revoked;
5. the bearer credential fingerprint matches;
6. the hostname matches the enrolled hostname.

The collector cannot assert that its own certificate or credential was
verified. Those are server-observed properties.

## Persistence

S3-4A intentionally introduces no schema migration.

A successful heartbeat reuses `authenticate_collector()` and therefore updates
the existing `collectors.last_seen_at` field.

A heartbeat does **not**:

- create a `collector_ingest_batches` row;
- enqueue analysis work;
- invoke rule detection;
- invoke ML;
- invoke correlation;
- create or update incidents.

Richer persistent operational/security-health fields belong to S3-4B.

## Collector transport

The collector runtime now supports:

- `collector_heartbeat_url`
- `build_heartbeat_payload()`
- `send_heartbeat()`
- `validate_heartbeat_response()`
- `DurableCollectorRuntime.heartbeat()`

The heartbeat transport uses the same CA bundle, client certificate, and
protected enrolled bearer credential as durable batch transport.

Certificate transition semantics are preserved: a successful authenticated
heartbeat can complete a locally staged certificate transition just like other
successful authenticated operations.

## Deployment

`deploy/windows/configure_collector_mtls.ps1` now writes the heartbeat endpoint:

```text
/api/collector/v1/heartbeat
```

No bootstrap token, recovery token, device credential, certificate bytes, or
private-key bytes are added to configuration by this change.
