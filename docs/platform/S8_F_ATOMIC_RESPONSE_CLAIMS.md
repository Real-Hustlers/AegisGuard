# S8-F — Atomic Response Claims

S8-F closes concurrent execution races in the response-governance state machine.

## Problem closed

Before S8-F, approval used a read-then-update sequence:

```text
read PENDING_APPROVAL
validate governance
set APPROVED
execute firewall
```

Two concurrent administrator requests could both read `PENDING_APPROVAL` before
either update committed. Because the later update did not require the row to
still be pending, both requests could enter firewall execution.

Rollback had the same pattern: two concurrent requests could both select the
same active `EXECUTED` AegisGuard-owned block and both call the firewall
removal adapter.

Request-level idempotency did not close these races because the duplicate
operation occurred after the single response-action record already existed.

## Approval claim

S8-F adds an atomic SQLite claim:

```text
UPDATE response_actions
SET status = APPROVED,
    approved_by_user_id = ...
WHERE id = ?
  AND status = PENDING_APPROVAL
```

The update runs inside `BEGIN IMMEDIATE`.

Exactly one concurrent approver can transition the action out of
`PENDING_APPROVAL`. A competing request receives the current response-action
state and does not call the firewall adapter.

S8-D identity separation and S8-E approval-context checks still occur before
the claim.

## Rollback claim

Live rollback now claims the owned action before invoking the firewall:

```text
status = EXECUTED
rollback_status = IN_PROGRESS
```

The claim is allowed only from a rollback state that is safe to retry:

```text
NULL / empty
FAILED
DRY_RUN
```

A second live rollback cannot claim an action already marked `IN_PROGRESS` or
`ROLLED_BACK`.

On success:

```text
status = ROLLED_BACK
rollback_status = ROLLED_BACK
```

On firewall failure:

```text
status = EXECUTED
rollback_status = FAILED
```

The existing retry behavior therefore remains available after an explicit
failure.

Dry-run rollback remains non-mutating and does not need an exclusive external
execution claim.

## Crash behavior

The claim is committed before the external firewall call.

If the process stops after claiming approval or rollback but before recording
the firewall result, the state remains `APPROVED` or `IN_PROGRESS` rather than
allowing another request to blindly repeat the external mutation.

This is fail-closed. Recovery/reconciliation can be handled explicitly rather
than risking duplicate response execution.

## Boundaries preserved

S8-F does not change:

- S8-E policy-context binding;
- S8-D maker/checker separation;
- S8-C AUTO qualification;
- S8-B rollback ownership rules;
- target validation or allowlists;
- deterministic firewall rule naming;
- incident/detection/ML/MITRE/correlation behavior;
- S7 privacy controls;
- S10 deployment/runtime behavior.
