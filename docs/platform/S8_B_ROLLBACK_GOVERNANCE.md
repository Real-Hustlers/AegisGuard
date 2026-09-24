# S8-B — Rollback Governance & Provenance

S8-B governs rollback of the constrained Analyzer-side IP block action.

## Problem closed

Before S8-B, `/api/soar/unblock-ip` selected the latest BLOCK_IP record for a
target regardless of whether that action actually created a firewall rule.

That allowed a pending, dry-run, policy-blocked, failed, or duplicate
`ALREADY_EXISTS` action to be treated as rollback ownership.

The old rollback path also:

- marked dry-run rollback as `ROLLED_BACK` even though the firewall was not
  changed;
- changed an executed block to `FAILED` when rollback failed, losing the fact
  that the block could still be active;
- reused block-eligibility validation, which could prevent restorative rollback
  after an IP was added to an allowlist or private blocking was disabled.

## Ownership rule

A rollback candidate must be an AegisGuard response action that:

- has `action_type = BLOCK_IP`;
- has `execution_scope = ANALYZER`;
- has `status = EXECUTED`;
- recorded `metadata.result = EXECUTED`, not merely `ALREADY_EXISTS`;
- recorded the deterministic AegisGuard firewall rule name for the target;
- has not already completed rollback.

This prevents removal based only on a matching target string.

## Restorative target validation

Blocking policy and rollback policy are different.

S8-B canonicalizes the requested IP address for rollback but does not require
that the address still be eligible for blocking. If policy later becomes more
restrictive, AegisGuard must still be able to remove a firewall rule that it
provably created.

Arbitrary firewall rules remain outside scope because rollback still requires
persisted AegisGuard ownership evidence and the deterministic rule name.

## Rollback lifecycle

Successful rollback:

```text
EXECUTED → ROLLED_BACK
rollback_status = ROLLED_BACK
```

Dry-run rollback:

```text
status remains EXECUTED
rollback_status = DRY_RUN
```

The firewall remains unchanged and the original `executed_at` is preserved.

Failed rollback:

```text
status remains EXECUTED
rollback_status = FAILED
```

The action remains retryable because the system must assume the original block
is still active when removal fails.

A later successful retry clears the rollback error and transitions to
`ROLLED_BACK`.

## Provenance

`/api/soar/unblock-ip` derives rollback actor identity from the authenticated
server-side session. The action metadata records
`rollback_requested_by_user_id`.

Sensitive-operation audit remains authoritative and additionally records the
resolved response-action ID and rollback status when present.

## Scope intentionally unchanged

S8-B does not change:

- MANUAL request/approval semantics established in S8-A;
- AUTO qualification or AUTO live-execution policy;
- firewall command construction;
- detection, ML, MITRE, correlation, or incident semantics;
- S7 privacy controls;
- S10 deployment/runtime behavior.

AUTO live-execution governance remains the next S8 decision.
