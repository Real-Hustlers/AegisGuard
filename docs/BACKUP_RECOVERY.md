# AegisGuard Enterprise Backup and Recovery

## Purpose

S14 defines a verifiable enterprise-state backup and restore contract for
AegisGuard Enterprise.

The recovery set is intentionally narrower than `%ProgramData%\AegisGuard`.
Mixed-sensitivity runtime directories are not copied wholesale.

## Backed-up state

### Analyzer database

The canonical Analyzer SQLite database is backed up with SQLite's online backup
API.

This preserves:

- normalized security events;
- incidents and unified incident history;
- audit ledger and its hash chain;
- collector/device registry state held by the Analyzer;
- durable Analyzer ingest queue state;
- users and role assignments;
- response-governance records;
- application settings.

Before the portable backup is archived, transient human sessions and login
throttle state are removed from the copied database. SQLite `secure_delete` is
enabled and the copied database is compacted after removal.

The production database is not modified.

### Collector configuration

Only the currently approved non-secret configuration keys are copied.

Certificate, CA, and private-key **path references** may be preserved because
the Collector needs to know where governed TLS material will be provisioned.
The certificate/private-key files themselves are never copied into the backup.

Unknown future config keys are omitted rather than copied implicitly.

### Collector local continuity state

The Collector state SQLite database is a mixed-sensitivity store. It can
contain:

- the stable Collector ID;
- checkpoint state;
- DPAPI-protected device credentials;
- pending credential/certificate transitions;
- queued event payloads.

S14 therefore creates a new safe projection instead of copying that database.

The projection includes only:

- `collector_id`;
- `last_acked_record_id`;
- `last_successful_ack_at`;
- active client-certificate path reference when present.

It excludes:

- protected or plaintext collector credentials;
- pending credential rotation;
- pending credential recovery;
- pending certificate rotation;
- all queued event payloads.

After a disaster recovery to a fresh Windows security context, the Collector
credential must be re-established using the existing governed credential
recovery flow.

### Governed ML registry

The backup includes only governed registry files:

- `metadata.json`;
- `active.json`;
- `model.joblib`;
- `encoder.joblib`.

Each model and encoder artifact must match the SHA-256 recorded in its metadata
before backup creation and again during restore verification.

Training datasets or arbitrary files under the registry root are not copied.

## Explicit exclusions

The backup archive does not include:

- session cookies or plaintext session tokens;
- active session database rows;
- login throttle transient state;
- Collector device credentials;
- enrollment/recovery bootstrap tokens;
- TLS private keys;
- TLS certificate files;
- CA certificate files;
- pending Collector credential/certificate transition state;
- Collector outbound event spool payloads;
- raw export files or customer-export artifacts;
- release binaries or installation media.

The Analyzer database remains security-sensitive because it is the canonical
enterprise evidence store. Backup media must therefore be protected with the
same access controls as the Analyzer data directory.

## Backup verification

Every backup contains a canonical `manifest.json` with:

- schema version;
- product and backup kind;
- deterministic backup ID derived from payload descriptors;
- component inventory;
- SHA-256 and size of every payload file;
- Analyzer evidence counts;
- audit-chain head hash;
- Collector continuity evidence;
- ML registry evidence;
- security-policy flags describing excluded material.

Verification fails closed on:

- malformed or duplicate ZIP paths;
- traversal paths;
- symlinks;
- missing payloads;
- unexpected payloads;
- size mismatch;
- SHA-256 mismatch;
- invalid Analyzer SQLite database;
- missing required Analyzer tables;
- invalid audit chain;
- non-empty restored session/login-throttle state;
- unsafe Collector config keys;
- unsafe Collector-state keys;
- queued Collector payloads;
- ML artifact hash mismatch;
- invalid active-model metadata.

## Source-free Windows command

S14 adds the PyInstaller entry point:

```text
AegisGuardRecovery.exe
```

The Windows offline bundle contains the compiled executable, not Python source.

The standard deployed paths are automatically resolved under
`%ProgramData%\AegisGuard`.

Example backup:

```powershell
AegisGuardRecovery.exe backup --output C:\ProgramData\AegisGuard\Backups\AegisGuard-enterprise-state.zip
```

Verify without changing the system:

```powershell
AegisGuardRecovery.exe verify --backup C:\ProgramData\AegisGuard\Backups\AegisGuard-enterprise-state.zip
```

Restore is plan-only by default:

```powershell
AegisGuardRecovery.exe restore --backup C:\ProgramData\AegisGuard\Backups\AegisGuard-enterprise-state.zip
```

After the Analyzer and Collector services have been stopped:

```powershell
AegisGuardRecovery.exe restore --backup C:\ProgramData\AegisGuard\Backups\AegisGuard-enterprise-state.zip --apply --services-stopped
```

## Restore safety

Restore verifies the entire backup before any target mutation.

An apply operation snapshots the current target state into a local protected
restore transaction. If the restore raises an ordinary failure, the original
targets are restored before the error is returned.

If the recovery process itself is interrupted after the transaction reaches
`APPLYING`, use the recorded transaction directory:

```powershell
AegisGuardRecovery.exe recover-transaction --transaction-directory C:\ProgramData\AegisGuard\Analyzer\AegisGuardRestoreTransactions\AGB-SAMPLE-20260925T040000Z
```

Completed or rolled-back transactions cannot be recovered a second time.

## Post-restore verification

After restore:

1. Re-provision TLS certificates/private keys and any recovery bootstrap secret
   through the existing deployment/credential lifecycle. These are excluded
   from portable backups.
2. Start the Analyzer.
3. Confirm `/readyz` reports ready.
4. Confirm audit integrity.
5. Confirm incidents and response actions are present.
6. Confirm Collector server-side identity is present.
7. Confirm restored Collector ID/checkpoint continuity.
8. Recover the Collector device credential if the local credential was lost.
9. Start the Collector.
10. Confirm authenticated heartbeat and mTLS.
11. Confirm any Analyzer ingest rows recovered from interrupted `PROCESSING`
    state are re-queued by the existing ingest recovery path.
12. Confirm governed ML is AVAILABLE when restored artifacts are compatible, or
    explicitly DEGRADED/UNAVAILABLE while rule/correlation processing remains
    available.
