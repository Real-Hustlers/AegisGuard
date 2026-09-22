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

## Y9.2 live Analyzer evidence capture

Y9.2 adds a GET-only evidence workflow for the actual isolated VM.

The tool refuses to start unless:

- legacy `simulation_mode` is `true`; and
- SOAR is either `OFF` or `soar_dry_run` is `true`.

It does not change those settings. If the Analyzer is unsafe, validation stops.

### 1. Record the baseline

Run this before producing the authorized test activity:

```powershell
python -m backend.analyzer.intelligence.live_evidence start `
  --analyzer-url http://127.0.0.1:5000 `
  --hostname YOUR-VM-HOSTNAME `
  --output .\.validation\y9-baseline.json
```

The baseline records the existing event IDs for that host and the current
response-safety settings.

### 2. Perform the authorized isolated-VM scenario

Generate the required security activity only inside the isolated test VM.
Do not target production or public systems. Keep AegisGuard response enforcement
in simulation/dry-run mode.

Allow the Collector to deliver the resulting Windows events to the Analyzer.

### 3. Finish and validate

```powershell
python -m backend.analyzer.intelligence.live_evidence finish `
  --baseline .\.validation\y9-baseline.json `
  --scenario credential-to-privilege `
  --output .\.validation\y9-credential-to-privilege.json
```

The finish operation:

1. rechecks response-safety settings;
2. fetches the target host's `/api/events`;
3. considers only event IDs that did not exist in the baseline;
4. validates those events with the Y9.1 deterministic validator;
5. fetches `/api/intelligence?event_limit=5000`;
6. independently verifies the expected findings, MITRE techniques, and attack
   stages are present for the same hostname;
7. writes one JSON evidence bundle.

No POST, PUT, PATCH, DELETE, approval, remediation, or response-execution API is
used by the evidence tool.

A successful report requires both the newly collected event validation and the
live Intelligence API verification to pass.
