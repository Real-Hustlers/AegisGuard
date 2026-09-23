# S7-E — Repository Data Hygiene

S7-E removes runtime Windows Security log artifacts that were still tracked in
the repository after S7-D disabled new plaintext raw-output copies by default.

## Removed from the current repository snapshot

- `/raw_security_logs.json`
- `/backend/collector/raw_security_logs.json`

The root artifact contained real Windows Security telemetry and therefore does
not belong in source control. The collector-local file was an empty legacy
placeholder and is also removed so there is one consistent policy.

## Prevention

The existing `.gitignore` rule for `raw_security_logs.json` remains in force.
A regression test verifies that the legacy artifact paths are absent and that
the S7-D default policy still disables local raw-output persistence.

## Scope boundary

This slice does not remove or modify ML-owned sample data, detection logic,
classification/correlation behavior, canonical analyzer evidence, audit data,
or response execution.

## Git history

Deleting these files removes them from the current branch snapshot, but it does
not rewrite earlier Git history. Historical purge is intentionally not
performed automatically because history rewriting is disruptive to active
branches and requires coordinated repository-owner action.
