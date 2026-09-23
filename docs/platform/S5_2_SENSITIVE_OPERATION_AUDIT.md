# S5-2 — Sensitive Security Operation Audit Wiring

S5-2 connects the S5-1 append-only audit foundation to security-sensitive
human application operations.

It does not add an audit query API, retention policy, or tamper-evidence.
Those belong to S5-3.

## Audited operations

### Authentication

```text
AUTH.LOGIN
AUTH.LOGOUT
```

Successful authentication is attributed to the user identity returned by the
trusted authentication service.

Failed or throttled login attempts use `actor_type=SYSTEM` because no human
identity has been authenticated. The attempted normalized username may be
stored as a target, but the password is never copied into audit details.

### Authorization failures

```text
AUTHORIZATION.DENIED
```

This covers:

- missing/invalid/expired sessions;
- insufficient RBAC role;
- missing/invalid CSRF token.

If the session was authenticated before the denial, the event is attributed to
that server-resolved user.

Otherwise the actor is SYSTEM.

Client-supplied role/user headers are never audit identity.

### Settings

```text
SETTINGS.UPDATE
```

Audit details record only changed setting keys. Values are deliberately not
copied into the audit record.

### Response approval

```text
RESPONSE.APPROVE
```

The response-action ID is the audit target.

### SOAR

```text
SOAR.BLOCK_IP
SOAR.UNBLOCK_IP
```

The IP address is the target. For block requests, the optional incident ID may
be retained as safe metadata. Reasons and arbitrary request-body fields are not
copied into the audit event.

### Incident operations

```text
INCIDENT.SIMULATE
INCIDENT.LIVE_EXECUTION_DENIED
INCIDENT.RESET
```

The legacy live-execution rejection remains visible as a denied security
event.

## Central classifier

`backend/analyzer/sensitive_audit.py` installs one Flask `after_request` hook.

The hook classifies only the known sensitive operations above and writes one
S5-1 audit event with:

- trusted server-side actor context;
- response-derived outcome;
- trusted peer IP;
- server-generated request correlation ID;
- safe, explicitly selected details.

It does **not** serialize arbitrary request bodies, request headers, response
bodies, cookies, credentials, or CSRF tokens.

## Failure behavior

Audit persistence errors are not swallowed.

A security-sensitive request must not appear successful to the HTTP caller if
its audit record could not be persisted.

S5-3 will add audit query authorization, retention policy, and tamper-evident
integrity validation.

## Deliberate boundary

S5-2 does not reclassify `/api/collector/v1/*` as human application audit.

Collector/device authentication remains the independent S3 trust boundary.
Collector-specific audit instrumentation can be added through its own trusted
COLLECTOR actor path without relying on human sessions.
