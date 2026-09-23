# S5-1 — Audit Event Foundation

S5-1 establishes the audit primitives used by the rest of S5.

It does **not** yet hook login, settings, incident, approval, SOAR, or collector
operations into the audit log. Route instrumentation belongs to S5-2.

## Existing persistence

The enterprise schema already contains:

```text
audit_events
```

from platform schema v1. S5-1 therefore introduces no database migration and
keeps `LATEST_PLATFORM_SCHEMA_VERSION = 8`.

## Append-only writer

`backend/storage/audit_log.py` provides the single audit insertion primitive.

Callers supply the event semantics:

- actor type;
- authenticated user ID when actor type is USER;
- action;
- outcome;
- optional target;
- peer IP;
- correlation ID;
- structured details.

The writer owns:

- `audit_id`;
- timestamp;
- normalization;
- validation;
- secret redaction;
- JSON serialization;
- persistence.

There is deliberately no audit update/delete helper.

## Actor types

Allowed actor types are:

```text
USER
SYSTEM
COLLECTOR
```

`USER` requires an existing `actor_user_id`.

`SYSTEM` and `COLLECTOR` do not accept an `actor_user_id`, preventing a
non-user event from masquerading as a human actor.

## Outcomes

Allowed outcomes are:

```text
SUCCESS
FAILURE
DENIED
```

## Secret redaction

Audit details recursively redact keys associated with:

- passwords/passphrases;
- credentials;
- authorization values;
- cookies;
- CSRF values;
- API/access/refresh/session tokens;
- private keys.

Bearer/basic authorization strings and PEM private-key values are also
redacted when encountered as generic scalar values.

Audit detail strings and total JSON size are bounded to avoid using the audit
log as an unbounded payload store.

## Server-generated request correlation

`backend/analyzer/audit_context.py` assigns a new correlation ID to every
Flask request:

```text
req-<random UUID>
```

It is returned as:

```text
X-AegisGuard-Correlation-ID
```

An incoming header with that name is not trusted as the canonical audit
correlation ID.

Later S5 hooks can retrieve:

- direct request peer IP;
- server-generated correlation ID;

through `current_request_audit_context()`.

## S5 boundaries

### S5-1

- audit persistence primitive;
- validation;
- secret redaction;
- request correlation foundation.

### S5-2

Instrument security-sensitive operations, including authentication,
authorization denials, settings changes, incident actions, approvals, and
SOAR requests.

### S5-3

Provide authorized audit querying, integrity/retention controls, and final
end-to-end audit validation.
