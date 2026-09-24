# S8-G — Interrupted Claim Reconciliation

S8-G adds explicit, fail-closed recovery for response claims interrupted after
S8-F atomically reserved execution.

## Problem closed

S8-F intentionally commits the database claim before calling Windows Firewall:

```text
PENDING_APPROVAL → APPROVED → firewall block
EXECUTED → rollback_status=IN_PROGRESS → firewall removal
```

That prevents duplicate concurrent execution, but a process or host failure in
the small window after the claim can leave durable intermediate state:

```text
APPROVED
IN_PROGRESS
```

Without reconciliation, those actions can remain stuck indefinitely.

## Recovery is explicit

S8-G does not automatically replay response actions during startup.

An authenticated administrator must call:

```text
POST /api/response-actions/<id>/reconcile
```

The actor identity is taken from the trusted server-side session. Client-supplied
identity fields are ignored.

## Stale-claim gate

A claim must be older than the recovery grace period before reconciliation is
allowed.

The default grace period is 60 seconds, which is deliberately longer than the
Windows Firewall command timeout used by the adapter.

A fresh claim returns:

```text
reconciliation_not_stale
```

This prevents the recovery path from racing a legitimate firewall operation that
is still running.

## APPROVED reconciliation

For a stale `APPROVED` action:

- a dry-run approval is deterministically completed as `DRY_RUN` without a
  firewall call;
- a live approval probes the exact deterministic AegisGuard rule;
- if the rule is absent, current policy context and target safety are rechecked
  before one controlled block attempt;
- if the rule already exists and another response action owns it, the recovered
  action records `ALREADY_EXISTS` and does not steal rollback ownership;
- if the rule exists with no prior active owner, the interrupted action is
  reconciled as the owner.

The original approving administrator remains unchanged.

## IN_PROGRESS rollback reconciliation

For a stale rollback claim:

- if the exact rule is already absent, the action is finalized as `ROLLED_BACK`
  without another removal call;
- if the rule still exists, AegisGuard performs one exact deterministic removal;
- firewall/probe failures become `FAILED`, preserving explicit retry behavior.

## Crash safety during reconciliation

Reconciliation runs under a SQLite `BEGIN IMMEDIATE` transaction while the
external rule state is inspected and, when required, changed.

If the process stops after the firewall mutation but before the database commit,
SQLite rolls the database transaction back. A later reconciliation probes the
actual deterministic rule state again instead of blindly repeating the prior
assumption.

This path is intentionally rare and administrator initiated; holding the write
claim across the bounded firewall operation is preferred to creating another
unrecoverable intermediate state.

## Audit

Reconciliation is audited as:

```text
action = RESPONSE.RECONCILE
```

with the trusted administrator identity, result status, rollback status, and any
stable denial code.

## Boundaries preserved

S8-G does not change:

- S8-F normal approval/rollback concurrency claims;
- S8-E approval-context binding;
- S8-D maker/checker separation;
- S8-C AUTO qualification;
- S8-B rollback ownership rules;
- deterministic firewall rule naming;
- incident/detection/ML/MITRE/correlation behavior;
- S7 privacy controls;
- S10 deployment/runtime behavior.
