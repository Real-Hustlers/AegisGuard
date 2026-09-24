# S8-C — AUTO Execution Governance

S8-C closes direct live execution from the AUTO request path.

The platform response sequence remains:

```text
OBSERVE
→ RECOMMEND
→ SIMULATE
→ APPROVAL
→ CONTROLLED EXECUTION
```

## Problem closed

Before S8-C, `soar_mode=AUTO` allowed a qualifying incident to call the
firewall adapter directly when `soar_dry_run=false`.

That bypassed the explicit approval stage defined by the platform response
contract.

The legacy `approved=True` argument to `request_block()` also remained capable
of request-side execution inside the engine even though S8-A removed that
shortcut from the HTTP API.

## S8-C invariant

`request_block()` never mutates the firewall.

Only `approve()` can call controlled block execution.

The `approved` request argument is retained temporarily for compatibility with
older internal callers, but it is ignored for authorization and cannot bypass
the approval state machine.

## AUTO semantics

AUTO now means automatic qualification and recommendation, not automatic live
firewall mutation.

A non-qualifying AUTO incident becomes:

```text
BLOCKED_BY_POLICY
```

A qualifying AUTO incident becomes:

```text
PENDING_APPROVAL
approval_required = 1
```

The action stores explainable qualification evidence in metadata:

- severity;
- threat/risk score;
- configured minimum score;
- correlated-brute-force indicator;
- qualification reasons;
- final qualified boolean.

The explicit approval endpoint remains administrator-only under existing S4
RBAC and CSRF controls.

After approval:

- `soar_dry_run=true` → `DRY_RUN`, no firewall mutation;
- `soar_dry_run=false` → constrained controlled execution through the existing
  AegisGuard Windows Firewall adapter.

## Qualification rules

S8-C does not change which incidents qualify for AUTO consideration.

Existing rules remain:

- `CRITICAL` severity; or
- score at or above `soar_auto_min_score`; or
- explicitly correlated `Possible Brute Force Attack`.

S8-C only changes what happens after qualification.

## Boundaries preserved

S8-C does not change:

- MANUAL approval semantics from S8-A;
- rollback governance from S8-B;
- target validation or allowlists;
- firewall rule construction;
- incident generation/detection semantics;
- ML, MITRE, or correlation logic;
- S7 privacy controls;
- S10 deployment/runtime behavior.

AUTO remains useful for automatically creating high-confidence response
recommendations, while live mutation remains an explicit controlled action.
