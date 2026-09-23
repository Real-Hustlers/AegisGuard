# S4-2 — Application RBAC and API Authorization

S4-2 applies the S4-1 human-user session to human-facing application APIs.

It does not replace or wrap the S3 collector/device trust path.

## Role policy

### VIEWER

VIEWER is read-only.

Authenticated VIEWER sessions may use GET/HEAD application APIs including:

- dashboard;
- alerts;
- events;
- devices;
- incidents;
- incident response logs;
- suspicious entities;
- settings reads;
- response-action reads;
- intelligence;
- alert summaries.

VIEWER cannot invoke application mutations.

### ANALYST

ANALYST includes VIEWER read access and may additionally invoke:

```text
POST /api/incidents/execute
```

That legacy route is simulation-only. The application already rejects
`enforce=true` and directs live response through the constrained SOAR path.

ANALYST cannot:

- change incident/SOAR settings;
- approve response actions;
- block or unblock IPs;
- reset incidents;
- use unclassified future mutation APIs.

### ADMINISTRATOR

ADMINISTRATOR can use all authenticated human application APIs, including
state-changing settings, response approvals, constrained SOAR operations, and
incident reset.

Any future non-GET `/api/*` human application route defaults to
ADMINISTRATOR until explicitly classified. This is intentionally fail-closed.

## Separate trust boundaries

These paths are excluded from human RBAC:

```text
/api/auth/*
/api/collector/v1/*
/api/upload_logs
```

`/api/auth/*` owns its S4-1 authentication lifecycle.

`/api/collector/v1/*` remains protected by the S3 collector credential/mTLS
model.

`/api/upload_logs` is retained as the legacy device-ingestion compatibility
surface. S4 does not incorrectly convert a device ingestion path into a human
session endpoint. Its eventual compatibility/deprecation handling must remain
explicit rather than being silently changed by RBAC.

The dashboard shell `/` remains public so a future login/session-aware
frontend can render before authentication. Data APIs are protected.

## Identity source

Authorization identity comes only from the validated persistent S4 session.

Client-supplied identity or role headers are ignored.

On successful authorization the server places the verified identity in:

```text
flask.g.aegisguard_user
```

This gives later phases a trustworthy actor source for audit, incident
ownership, and response governance.

## Response semantics

Missing, invalid, expired, revoked, or inactive-user sessions receive:

```text
401 authentication_required
```

Authenticated users with insufficient role receive:

```text
403 forbidden
```

## S4-3 boundary

S4-3 remains responsible for browser/session hardening beyond RBAC, including
the final state-changing-request protections and end-to-end application
security closure.
