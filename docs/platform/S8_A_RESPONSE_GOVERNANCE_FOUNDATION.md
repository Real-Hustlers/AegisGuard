# S8-A — Response Governance Foundation

S8-A begins AegisGuard Enterprise/SIEM response governance.

The platform response sequence is:

```text
OBSERVE → RECOMMEND → SIMULATE → APPROVAL → CONTROLLED EXECUTION
```

## Gap closed

Before S8-A, `/api/soar/block-ip` passed `approved=True` directly into the
SOAR engine. In MANUAL mode, the request could therefore count as its own
approval and proceed immediately when dry-run was disabled.

The engine also allowed `approve()` to continue actions that were not actually
pending approval, including policy-blocked or OFF-mode actions.

## S8-A behavior

For a valid MANUAL block request:

1. the authenticated administrator creates the request;
2. the action is persisted as `PENDING_APPROVAL`;
3. the trusted session user is stored in `requested_by_user_id`;
4. no firewall action occurs at request time;
5. `/api/response-actions/<id>/approve` is the explicit approval gate;
6. the trusted approving session user is stored in `approved_by_user_id`;
7. dry-run remains non-mutating and records `simulation_result`;
8. live execution continues to use the existing constrained Windows Firewall
   adapter when policy permits and dry-run is disabled.

Only `PENDING_APPROVAL` actions may enter the approval path. `SKIPPED`,
`BLOCKED_BY_POLICY`, `EXECUTED`, `DRY_RUN`, `FAILED`, and `ROLLED_BACK`
actions remain unchanged.

S8-A uses governance columns already present in the schema:
`requested_by_user_id`, `approved_by_user_id`, `approval_required`,
`simulation_result`, and `updated_at`.

## Boundaries preserved

S8-A does not alter collector trust, S7 privacy controls, S10 deployment/runtime
paths, detection/ML/MITRE/correlation, incident lifecycle, target validation,
allowlists, firewall command construction, AUTO qualification thresholds, or
rollback behavior.

AUTO live-execution governance and rollback governance remain later S8 slices.
