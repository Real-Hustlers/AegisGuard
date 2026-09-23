# S5-3 — Audit Query Authorization, Retention, Integrity, and Closure

S5-3 closes the AegisGuard audit phase.

## Schema v9

Platform schema v9 adds four audit-chain fields:

```text
chain_sequence
previous_hash
event_hash
retention_until
```

Existing audit rows are backfilled in original SQLite row order into a single
SHA-256 chain.

New events append to the current chain head.

The hash covers the complete persisted audit event, including:

- sequence;
- audit ID;
- timestamp;
- actor;
- action;
- target;
- outcome;
- peer IP;
- correlation ID;
- exact details JSON;
- retention deadline;
- previous hash.

Modification, deletion, reordering, or sequence gaps are therefore detectable.

## Retention

Default audit retention is:

```text
365 days
```

Configuration:

```text
AEGISGUARD_AUDIT_RETENTION_DAYS
```

Allowed range is 1–3650 days.

Each audit row records its own `retention_until`.

A SQLite trigger rejects deletion while that deadline is active. There is no
HTTP delete endpoint for audit evidence.

The hash chain still detects deletion after retention expiry unless an
explicit future archival/compaction design deliberately establishes a new
trusted anchor.

## Administrator-only evidence APIs

S5-3 adds:

```text
GET /api/audit/events
GET /api/audit/integrity
```

Both are ADMINISTRATOR-only even though normal AegisGuard GET APIs are readable
by all authenticated roles.

`/api/audit/events` supports bounded, parameterized filters:

- limit (1–500);
- action;
- outcome;
- actor_type;
- correlation_id;
- target_id.

`/api/audit/integrity` reports:

- validity;
- event count;
- first/last chain sequence;
- head hash;
- failure sequence/reason;
- configured retention days.

## Audit access is audited

Successful audit-log reads emit:

```text
AUDIT.READ
```

Successful integrity checks emit:

```text
AUDIT.VERIFY
```

Authorization failures continue to emit:

```text
AUTHORIZATION.DENIED
```

The query response is calculated before its own access event is appended, so a
read never recursively contains itself.

## Integrity behavior

Audit verification is tamper-evident, not a substitute for filesystem and
database access control.

A process with raw database write access can still alter SQLite bytes, but the
chain verifier detects changed event content, broken linkage, and missing or
reordered sequence numbers.

## S5 completion

After S5-3 merge, S5 provides:

1. append-only application audit writer;
2. server-generated actor/correlation context;
3. recursive secret redaction;
4. sensitive-operation instrumentation;
5. administrator-only evidence retrieval;
6. per-event retention deadlines;
7. active-retention delete protection;
8. SHA-256 chain integrity verification;
9. final end-to-end tests for authorization, retention, and tamper detection.

The next product phase is S6 — Incident Platform.
