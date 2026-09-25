# S12-A — Enterprise Security End-to-End Validation

## Scope

S12-A validates the integrated AegisGuard Enterprise security/backend lifecycle
against the product components already present on `product/integration`.

Baseline audited before implementation:

```text
3391984726bd99b6a8163566c44aeb199498a688
```

Latest relevant merged change at that baseline:

```text
PR #120 — Add S11-D governed transaction rollback
```

S12-A adds validation and evidence only. It does not add a new detection,
response, collector, ML, or incident feature.

## Architecture path validated

The deterministic E2E suite exercises this path:

```text
Security Activity
    ↓
Authenticated Collector + mTLS identity
    ↓
Durable collector batch persistence
    ↓
Durable ingest worker
    ↓
Normalization + persisted security event
    ↓
Rule Engine
    ↓
Governed ML state
    ↓
Correlation
    ↓
MITRE ATT&CK mapping
    ↓
Attack-story IncidentCandidate
    ↓
Unified incident persistence
    ↓
Response governance
    ↓
Separation of duties + dry-run approval
    ↓
Human RBAC/privacy boundaries
    ↓
Tamper-evident audit evidence
```

## Real component boundaries

The suite uses the existing production components directly:

- `create_collector_blueprint`
- collector credential authentication
- collector certificate/mTLS identity verification
- `persist_collector_batch`
- `CollectorIngestWorker`
- `process_collector_payload`
- `normalize_collector_payload`
- the existing analyzer classifier/persistence path
- `RuleEngine`
- `GovernedMLRuntime`
- the real `MLEngine`
- `CorrelationEngine`
- the canonical MITRE catalog
- attack-story construction
- `persist_incident_candidate`
- `SoarEngine`
- `ResponsePolicy`
- the authentication blueprint
- application RBAC/CSRF middleware
- incident API blueprint
- privacy projection
- sensitive-operation audit instrumentation
- `verify_audit_chain`

No test-only replacement is used for detection, ML inference, correlation,
MITRE mapping, incident persistence, authentication, authorization, durable
storage, or response policy.

The only response dependency substituted is a fail-if-called firewall sentinel.
The validated response path uses `soar_dry_run=true`, so a call to live firewall
mutation is itself a test failure.

## Deterministic security activity

The main lifecycle uses five normalized Windows-style events on one host:

1. failed authentication;
2. failed authentication;
3. failed authentication;
4. successful authentication;
5. privilege-escalation activity.

The real intelligence stack therefore has deterministic evidence for:

- failed-authentication rules;
- brute-force correlation;
- Credential Access ATT&CK mapping `T1110`;
- Privilege Escalation ATT&CK mapping `T1548`;
- a multi-stage attack story suitable for the unified incident contract.

## Collector and durable-ingest evidence

The suite verifies:

- enrollment requires the configured bootstrap boundary;
- mTLS identity is present at enrollment/ingestion;
- collector credential authentication is enforced;
- the batch is acknowledged only after durable persistence;
- a duplicate delivery returns duplicate=true;
- one batch ID exists in durable queue storage;
- the worker moves the batch through processing to `PROCESSED`;
- five events are persisted exactly once;
- successful processing removes the durable raw batch payload copy.

A separate restart test claims a batch into `PROCESSING`, invokes the existing
interrupted-ingest recovery path, and proves the batch returns to `QUEUED`,
processes successfully on the second attempt, and does not duplicate events.

## Intelligence and ML evidence

### Governed ML degraded

The main lifecycle supplies the existing `GovernedMLRuntime` in `DEGRADED`
state and verifies:

- governed ML emits no finding;
- deterministic rule findings are still produced;
- correlation findings are still produced;
- MITRE coverage remains present;
- the attack story remains constructible.

This proves the platform does not make rule/correlation availability depend on
governed ML availability.

### Governed ML available

A separate test trains a small deterministic scikit-learn
`RandomForestClassifier` in memory and supplies it through the real
`MLEngine` and `GovernedMLRuntime(AVAILABLE)` contracts.

It verifies that the emitted ML finding preserves:

- detection type `ML`;
- model name/source;
- model version;
- feature schema version;
- confidence-backed inference;
- MITRE mapping.

No fake model object is used.

## Incident persistence

The intelligence snapshot is intentionally read-only in the current product.

Therefore S12-A does **not** claim that `GET /api/intelligence` automatically
writes an incident. Instead, the E2E validation takes the real attack-story
`IncidentCandidate` produced by the intelligence layer and passes that same
contract to the real unified incident service.

The suite verifies:

- the candidate creates a durable incident;
- an identical retry is idempotent;
- the incident begins in the expected lifecycle state;
- restart/reopen preserves the incident;
- the incident creation audit event exists exactly once.

This explicit handoff reflects the current architecture rather than inventing
an automatic persistence bridge.

## Response-governance evidence

The suite verifies:

- the existing ingest path produces response recommendations;
- a unified incident can request the existing governed `BLOCK_IP` action;
- the response begins in `PENDING_APPROVAL`;
- the requester cannot approve their own action;
- the authorization contract keeps response approval administrator-only;
- a different approver can approve;
- `soar_dry_run=true` produces `DRY_RUN`;
- no live firewall operation is invoked;
- requester, approver, status, and simulation result remain persisted after
  reopening the database.

The persisted `response_actions` row is the response action ledger. S5
hash-chain audit evidence separately covers security-sensitive human API
operations.

## Authentication, RBAC, privacy, and attribution

The human API portion uses the real authentication, incident, authorization,
privacy, and audit components.

It verifies:

- Viewer can read an incident but cannot mutate it;
- Viewer security-sensitive telemetry is redacted;
- Analyst sees the operational telemetry required for SOC work;
- Analyst can perform an allowed lifecycle transition;
- Analyst cannot use the administrator-only assignment operation;
- Administrator can assign the incident;
- CSRF tokens are required for mutations;
- forged identity/role headers do not replace server-authenticated identity;
- the audit event attributes the mutation to the authenticated user;
- unified incident output does not expose embedded raw event bodies.

## Audit integrity

After the complete workflow the test reopens the SQLite database and runs the
existing `verify_audit_chain` implementation.

The chain must remain valid after:

- incident creation;
- authentication events;
- authorization denial;
- incident transition;
- incident assignment.

## Defects fixed

No production defect was changed by this S12-A slice.

The audit did identify an important architecture boundary: governed
intelligence snapshots are read-only and are not themselves an automatic
incident-persistence pipeline. S12-A records this accurately and validates the
existing `IncidentCandidate` → unified incident service handoff directly.

## Known limitations

This deterministic suite is backend integration evidence, not a substitute for
the already-existing Windows deployment and transport proofs.

Specifically:

- Flask's test client supplies the verified client-certificate WSGI boundary;
  it does not establish a real TCP/TLS handshake.
- Actual Windows service installation and packaged-runtime behavior remain
  covered by the existing S3/S10 validation.
- The response test deliberately validates simulation/dry-run and never
  performs a live firewall mutation.
- The suite does not claim that the read-only intelligence endpoint
  automatically persists unified incidents.
- The in-memory training data exists only inside the test process and is not a
  production model artifact.

## Validation gate

Run:

```text
python -m pytest tests/e2e -q
python -m pytest tests/platform -q
python -m pytest tests/intelligence -q
python -m pytest backend/analyzer/test -q
python -m pytest backend/collector/test_live_monitoring.py -q
git diff --check
git status --short
```

S12-A is complete only when the actual command output is recorded and all
required gates pass.
