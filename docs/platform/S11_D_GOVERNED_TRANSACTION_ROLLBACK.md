# S11-D — Governed Transaction Rollback

## Purpose

S11-C creates a verified backup transaction before upgrading the Windows
enterprise binaries and automatically restores those files if the upgrade
itself fails.

S11-D closes the next lifecycle gap: an administrator may later roll back a
successful S11-C upgrade using the exact prior installed artifacts stored by
that transaction.

## Rollback command

The source-free Windows enterprise bundle includes:

```text
deploy/windows/rollback_enterprise.ps1
```

Plan-only preflight is the default:

```text
powershell -ExecutionPolicy Bypass -File deploy/windows/rollback_enterprise.ps1 -TransactionId 0123456789ab-20260925T030000Z
```

The script changes nothing unless `-Apply` is supplied.

## Fail-closed transaction validation

Before any mutation, S11-D requires:

- the S11-C transaction ID format;
- a transaction directory directly beneath the configured UpgradeBackups root;
- schema version 1 transaction metadata;
- matching transaction ID;
- a valid 40-character source commit;
- `runtime_state_policy = preserve_programdata`;
- exactly the six approved Analyzer/Collector Program Files artifacts;
- no duplicate or unapproved target paths;
- backup paths exactly inside the selected transaction directory;
- each backup SHA-256 to match `PreviousSha256`;
- each currently installed artifact SHA-256 to match `ReleaseSha256`.

The last check prevents an old transaction from silently overwriting a
different or manually modified installed release.

## Apply behavior

With `-Apply`, S11-D:

1. requires Administrator privileges;
2. records which AegisGuard scheduled tasks are currently running;
3. stops only those running tasks;
4. creates a rollback-recovery copy of the current installed release;
5. verifies the recovery-copy hashes;
6. records a non-secret `rollback-attempt.json`;
7. restores the six prior Program Files artifacts from the S11-C transaction;
8. verifies every restored artifact against its recorded previous SHA-256;
9. restarts the tasks that were running before rollback.

If the rollback itself fails, S11-D restores the current release from the
rollback-recovery copy and restarts the prior running tasks before re-raising
the error.

## Runtime-state boundary

S11-D does not roll back or replace ProgramData application state.

It does not modify:

- `aegisguard.db`;
- ML registry contents;
- `collector_state.db`;
- `config.json`;
- TLS certificates or private keys;
- enrollment/recovery credentials;
- customer logs.

This is intentional. S11-D is valid only for S11-C transactions whose runtime
state policy is `preserve_programdata`.

## Scope boundary

S11-D rolls back one recorded S11-C upgrade transaction. It is not a generic
arbitrary-file restore utility and it does not claim schema-migration rollback.

A future schema-changing release would require an explicit data migration and
rollback contract before this binary rollback mechanism could be used safely.

## Validation gate

```text
python -m pytest tests/deployment/test_s11d_governed_transaction_rollback.py -q
python -m pytest tests/deployment -q
python -m pytest tests/platform -q
python -m pytest tests/intelligence -q
python -m pytest tests/frontend -q
python -m pytest backend/collector/test_live_monitoring.py -q
python -m pytest backend/analyzer/test -q
git diff --check
```
