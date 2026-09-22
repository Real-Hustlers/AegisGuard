# Y9 Authorized Isolated VM Detection Validation

## Purpose

Y9 validates that AegisGuard Enterprise can detect a controlled sequence of
security events captured from an **authorized isolated virtual machine** and
present the expected Rule, Correlation, MITRE ATT&CK, and multi-stage attack
story evidence.

This phase validates detection. It does not authorize offensive activity
against external systems and it does not enable automatic response execution.

## Safety boundary

Use only a VM and network that the operator owns or is explicitly authorized to
test.

Recommended lab boundary:

- isolated or host-only virtual network
- no route to production systems
- no public target
- AegisGuard response enforcement disabled or dry-run only
- snapshots/checkpoints available for recovery
- test accounts and test data only

## Y9.1 validation harness

The validator consumes normalized AegisGuard event captures. It does not
generate attacks itself.

Supported scenarios:

### `credential-to-privilege`

Expected evidence:

- `AG-RULE-AUTH-001`
- `AG-CORR-AUTH-001A`
- `AG-CORR-AUTH-001B`
- `AG-CORR-PRIV-001A`
- MITRE `T1110`
- MITRE `T1098.007`
- attack stages `CREDENTIAL_ACCESS` and `PRIVILEGE_ESCALATION`

### `discovery-to-persistence`

Expected evidence:

- `AG-CORR-DISC-001`
- `AG-CORR-PERSIST-001`
- MITRE `T1069.001`
- MITRE `T1136`
- attack stages `DISCOVERY` and `PERSISTENCE`

## Input

The input may be either a JSON list of normalized event dictionaries or a
Collector-style object containing a `logs` list.

Each event must include at least:

- `timestamp`
- `event_type`

For real validation, retain host, user, source IP, process, record ID, and raw
event data whenever the Collector provides them.

## Run

```powershell
python -m backend.analyzer.intelligence.lab_validation `
  --scenario credential-to-privilege `
  --input .\lab-capture.json `
  --output .\lab-report.json
```

Exit codes:

- `0` — all expected evidence observed
- `1` — valid capture, but one or more expected detections are missing
- `2` — invalid scenario or input

## Evidence to retain for Y9 completion

For every real-VM scenario, retain:

1. VM/network isolation proof.
2. Collector identity and Analyzer identity.
3. Source event record IDs and timestamps.
4. Normalized captured events.
5. Y9 validation JSON report.
6. `/api/intelligence` snapshot showing the corresponding findings.
7. Dashboard screenshot showing the Intelligence workspace.
8. Confirmation that response enforcement remained disabled or dry-run.

Y9.1 establishes the deterministic validator. A later Y9 slice performs the
real authorized VM run and records the resulting evidence.
