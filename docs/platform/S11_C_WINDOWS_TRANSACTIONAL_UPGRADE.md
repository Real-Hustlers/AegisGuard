# S11-C — Windows Transactional Upgrade & Automatic Rollback

## Purpose

S10 installs the packaged Analyzer and Collector into the Windows enterprise
layout. S11-A and S11-B validate release integrity and trusted release pins.

S11-C closes the next deployment lifecycle gap: upgrading an existing
enterprise installation without overwriting durable runtime state and without
leaving a partially upgraded binary set after a copy failure.

## Upgrade command

The new source-free bundle contains:

```text
deploy/windows/upgrade_enterprise.ps1
```

Preflight / plan-only mode is the default:

```text
powershell -ExecutionPolicy Bypass -File deploy/windows/upgrade_enterprise.ps1 -BundleDirectory .\AegisGuard-Windows-Enterprise
```

No installed file or scheduled task is changed unless `-Apply` is supplied.

An operator may additionally bind the extracted bundle to an independently
trusted source commit with `-ExpectedSourceCommit`.

## Apply behavior

With `-Apply`, S11-C:

1. verifies the S10E manifest and SHA-256 coverage before any mutation;
2. rejects dirty-source release manifests;
3. optionally enforces the trusted source-commit pin;
4. confirms the target is an existing enterprise installation;
5. records which AegisGuard scheduled tasks were running;
6. stops only those running AegisGuard tasks;
7. backs up current Program Files binaries and runner scripts;
8. writes a non-secret `transaction.json` record;
9. copies the verified release binaries and runner scripts into the same paths;
10. hashes installed copies against release files;
11. restores previously running tasks.

If a mutation step fails, backed-up installed files are restored and previously
running tasks are restarted before the error is re-raised.

## Runtime-state boundary

S11-C upgrades only Program Files artifacts. It does not replace or delete
Analyzer databases, the ML registry, Collector durable state, Collector
configuration, TLS material, credentials, or customer logs.

Upgrade backups are stored separately under:

```text
%ProgramData%\AegisGuard\UpgradeBackups
```

They contain only prior installed binaries/runner scripts and non-secret
transaction metadata.

## Scope boundary

S11-C provides automatic rollback on upgrade failure. It is not a general
operator-directed rollback-to-any-historical-release feature.

It does not modify application runtime behavior, schemas, collector trust,
privacy policy, response governance, or detection logic.

## Validation gate

```text
python -m pytest tests/deployment/test_s11c_windows_transactional_upgrade.py -q
python -m pytest tests/deployment -q
python -m pytest tests/platform -q
python -m pytest tests/intelligence -q
python -m pytest tests/frontend -q
python -m pytest backend/collector/test_live_monitoring.py -q
python -m pytest backend/analyzer/test -q
git diff --check
```
