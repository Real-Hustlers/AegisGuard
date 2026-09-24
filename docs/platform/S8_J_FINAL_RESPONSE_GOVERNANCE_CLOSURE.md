# S8-J — Final Response Governance Closure

S8-J is the final closure gate for the AegisGuard Enterprise/SIEM S8
Response Governance workstream.

It introduces no new response architecture. It records the merged S8 controls,
verifies the critical safety invariants end to end, and defines the boundaries
that future response features must preserve.

## S8 control matrix

| Slice | Control | Closure state |
| --- | --- | --- |
| S8-A | Explicit response approval foundation | Implemented |
| S8-B | Rollback ownership, provenance, and retry-safe failure handling | Implemented |
| S8-C | AUTO recommendation governance without automatic execution | Implemented |
| S8-D | Human requester/approver separation of duties | Implemented |
| S8-E | Approval context binding and policy-change invalidation | Implemented |
| S8-F | Atomic approval and rollback claims | Implemented |
| S8-G | Interrupted claim reconciliation | Implemented |
| S8-H | Explicit terminal rejection lifecycle | Implemented |
| S8-I | Governed retry of previously approved failed execution | Implemented |
| S8-J | Final merged-tree response governance closure | Implemented |

## Final governed lifecycle

AegisGuard's live Analyzer-side response path is:

```text
OBSERVE
→ RECOMMEND / REQUEST
→ PENDING_APPROVAL
→ APPROVE
→ DRY_RUN or controlled live execution
```

Alternative and recovery paths are:

```text
PENDING_APPROVAL → REJECTED

APPROVED interrupted
→ explicit stale-claim reconciliation
→ DRY_RUN / EXECUTED / FAILED / BLOCKED_BY_POLICY

FAILED
→ governed retry
→ atomic APPROVED claim
→ EXECUTED or FAILED

EXECUTED owned block
→ governed rollback claim
→ ROLLED_BACK or retryable rollback FAILED
```

## Authorization boundary

Human response mutations remain protected by the application session,
role-based authorization, and CSRF controls.

The following POST surfaces are administrator-only:

```text
/api/soar/block-ip
/api/soar/unblock-ip
/api/response-actions/<id>/approve
/api/response-actions/<id>/reject
/api/response-actions/<id>/retry
/api/response-actions/<id>/reconcile
/api/incidents/settings
```

Trusted actor identities are taken from the authenticated server-side session,
not request JSON.

## No direct automatic live execution

MANUAL requests are persisted as `PENDING_APPROVAL`.

AUTO qualification can recommend containment, but a qualifying AUTO event is
also persisted as `PENDING_APPROVAL`. Qualification never directly calls the
firewall.

For a human-created action, requester and approver must be different trusted
users.

A system-generated AUTO recommendation has no human requester and may be
approved by a trusted administrator.

## Approval validity

Approval is bound to the execution-relevant response policy captured when the
request was created.

Before live execution, AegisGuard also revalidates current target safety,
including:

- allowlist membership;
- Analyzer addresses;
- known Collector addresses;
- loopback/unspecified addresses;
- multicast/reserved/broadcast addresses;
- private-address policy.

A response-policy change therefore invalidates an older pending approval rather
than silently changing its execution meaning.

Pending approvals do **not** currently have a wall-clock TTL. This is an
intentional documented boundary, not an implied guarantee. Their authority is
instead constrained by explicit human approval, policy-context binding, current
target revalidation, atomic claiming, and the explicit reject operation.

If a deployment requires time-limited approvals, approval expiry must be added
as a separately specified policy with clear re-request semantics rather than by
silently expiring deterministic action keys.

## Atomicity and recovery

Approval, retry, and live rollback use conditional SQLite claims so concurrent
operators cannot duplicate the same external mutation.

A claim is committed before the normal external firewall call. S8-G provides an
explicit administrator reconciliation path for stale interrupted claims.

Recovery probes the exact deterministic AegisGuard-owned Windows Firewall rule
rather than blindly replaying a mutation.

## Rejection

`REJECTED` is terminal.

A rejected action cannot later be approved into execution and rejection never
calls the firewall.

## Failed execution retry

A retry does not create new approval authority.

Only a previously approved `FAILED` action can be retried. The original
approver identity remains unchanged, the original S8-E approval context must
still match, and current target safety is revalidated.

## Rollback ownership

AegisGuard only treats a block as rollback-owned when the response action
records an actual AegisGuard execution with the exact deterministic firewall
rule.

An `ALREADY_EXISTS` result does not steal rollback ownership from the action
that originally created the rule.

Dry-run rollback is non-mutating. Failed live rollback remains retryable.

## Execution surface boundary

The only supported real response mutation in S8 is the constrained
Analyzer-side Windows Firewall IP block/unblock path.

The legacy:

```text
POST /api/incidents/execute
```

remains simulation-only and rejects live `enforce=true`.

S8 does not enable arbitrary PowerShell, generic host command execution, or
remote Collector/endpoint command delivery.

## Audit

Sensitive response operations are represented in the integrity-protected audit
chain, including:

```text
RESPONSE.APPROVE
RESPONSE.REJECT
RESPONSE.RETRY
RESPONSE.RECONCILE
SOAR.BLOCK_IP
SOAR.UNBLOCK_IP
SETTINGS.UPDATE
```

Authorization failures remain separately audited by the application security
layer.

## Deployment boundaries

S8 response execution is Windows Firewall-specific.

S8 does not claim:

- cross-platform host response;
- EDR/vendor response integration;
- network-device ACL orchestration;
- automatic pending-approval expiry;
- dual-control for response-setting changes;
- authenticated remote Collector command execution.

Those require separately designed trust, authorization, recovery, and audit
contracts.

## Scope intentionally unchanged

S8 does not modify:

- collector authentication or mTLS;
- durable collector transport;
- event collection;
- detection/classification;
- ML scoring;
- MITRE mapping;
- incident correlation semantics;
- S7 evidence/privacy controls;
- S10 Windows deployment/runtime ownership.

## Closure gate

S8 is technically closed when:

- S8-J focused closure tests pass;
- S8-A through S8-I focused tests pass;
- SOAR engine/API and sensitive-audit regressions pass;
- platform/intelligence/frontend/deployment/collector/analyzer regressions pass;
- `git diff --check` is clean;
- S8-J is merged into `product/integration`.

Future response actions or integrations must re-apply the same principles:
least privilege, explicit authorization, trusted identity, deterministic
ownership, policy binding, atomic external-mutation claims, recovery,
provenance, auditability, and fail-closed behavior.
