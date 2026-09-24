# S8-I — Governed Failed-Execution Retry

S8-I closes the response lifecycle gap created when an approved live firewall
operation fails for a transient technical reason.

## Problem closed

A response action uses a deterministic `action_key` for idempotency.

After an approved live execution fails, the row becomes:

```text
FAILED
```

A repeated block request returns that same row because the `action_key` already
exists, while `approve()` only operates on `PENDING_APPROVAL`.

Without S8-I, a transient firewall failure therefore makes the approved action
permanently non-executable even after the underlying problem is fixed.

## Retry does not create new approval authority

Retry is allowed only when all of the following remain true:

- the action is `BLOCK_IP`;
- the action status is `FAILED`;
- a trusted administrator initiates the retry;
- a bounded, non-empty retry reason is supplied;
- the action still has its original trusted `approved_by_user_id`;
- response mode is not `OFF`;
- the original S8-E approval context still matches current response policy;
- the target still passes current safety validation.

A retry does not replace or modify the original approver identity.

The original maker/checker approval therefore remains the authorization basis.

## Atomic retry claim

Retry uses the same fail-closed execution shape introduced by S8-F:

```text
FAILED
→ atomic claim
→ APPROVED
→ firewall execution
→ EXECUTED or FAILED
```

Only one concurrent retry can claim the `FAILED` row. A losing retry observes
the state created by the winner and does not call the firewall adapter.

Because the retry claim uses `APPROVED`, the interrupted-claim reconciliation
added in S8-G also covers a crash between the retry claim and external firewall
result persistence.

## Policy changes fail closed

Retry reuses the original approval context stored by S8-E.

If response mode is OFF, policy context changed, approval context is missing, or
the target is newly protected/allowlisted, the retry is denied and the action
remains `FAILED`.

This preserves retryability if an administrator later intentionally restores an
eligible policy configuration.

## Provenance

Response metadata records:

```text
retry_count
retry_history[].by_user_id
retry_history[].reason
retry_history[].at
retry_history[].previous_error
```

The full bounded retry reason stays with the response action.

Each HTTP retry is also recorded as:

```text
RESPONSE.RETRY
```

in the integrity-protected sensitive-operation audit chain.

## HTTP API

```text
POST /api/response-actions/<id>/retry
```

Payload:

```json
{
  "reason": "transient Windows Firewall service recovered"
}
```

Stable governance errors include:

```text
retry_identity_required
retry_reason_required
retry_reason_too_long
retry_not_available
retry_approval_missing
response_mode_off
approval_context_missing
response_policy_changed
retry_target_blocked
```

## Storage

No schema migration is required.

S8-I reuses the existing status, approval identity, error, metadata and timestamp
fields.

## Boundaries preserved

S8-I does not change:

- S8-H explicit rejection;
- S8-G interrupted-claim reconciliation;
- S8-F normal approval/rollback atomic claims;
- S8-E approval-context binding;
- S8-D maker/checker separation;
- S8-C AUTO qualification;
- S8-B rollback ownership;
- deterministic firewall naming;
- incident/detection/ML/MITRE/correlation behavior;
- S7 privacy controls;
- S10 deployment/runtime behavior.
