# S8-H — Explicit Rejection Lifecycle

S8-H closes the pending-response decision lifecycle by adding an explicit
governed rejection path.

## Problem closed

AegisGuard's platform contract already defines `REJECTED`, but the SOAR runtime
previously had no rejection operation.

A response action could therefore become:

```text
PENDING_APPROVAL
```

and then only be approved, blocked by a later policy check, or remain pending
indefinitely.

That is incomplete approval governance because "do not execute this action" was
not represented as an explicit durable decision.

## S8-H lifecycle

The governed human decision path becomes:

```text
REQUEST / RECOMMEND
→ PENDING_APPROVAL
→ APPROVE → controlled execution
   OR
→ REJECT → REJECTED
```

`REJECTED` is terminal for the response action. Calling `approve()` afterward
returns the rejected action unchanged and does not call the firewall.

## Trusted identity and reason

Rejection requires:

- a trusted server-side administrator identity;
- a non-empty rejection reason;
- a reason no longer than 500 characters.

The client cannot supply or override `rejected_by_user_id`.

Rejection provenance is stored in response metadata:

```text
rejection.by_user_id
rejection.reason
rejection.at
```

The original request reason remains unchanged.

A requester is allowed to reject their own still-pending request. This is a safe
withdrawal operation because rejection can only reduce execution authority; it
never enables firewall mutation.

System-generated AUTO recommendations can also be rejected by an administrator.

## Atomic decision

Rejection uses an atomic conditional update:

```text
UPDATE response_actions
SET status = REJECTED
WHERE id = ?
  AND status = PENDING_APPROVAL
```

Approval already uses the corresponding atomic pending-to-approved claim.

If approval and rejection race, exactly one decision can leave
`PENDING_APPROVAL`. The losing operation observes the already-decided state and
does not perform an external mutation.

## HTTP API

```text
POST /api/response-actions/<id>/reject
```

Payload:

```json
{
  "reason": "reason for rejecting containment"
}
```

Stable validation/governance errors:

```text
rejection_identity_required
rejection_reason_required
rejection_reason_too_long
```

## Audit

Rejection is audited as:

```text
action = RESPONSE.REJECT
```

The audit actor is the trusted authenticated administrator. The durable response
action contains the full rejection reason; the sensitive-operation audit stores
decision status and stable error codes without duplicating free-form reason text.

## Storage

No schema migration is required.

S8-H uses the existing response-action status and metadata fields.

## Boundaries preserved

S8-H does not change:

- S8-G interrupted-claim reconciliation;
- S8-F atomic approval and rollback claims;
- S8-E approval-context binding;
- S8-D maker/checker approval separation;
- S8-C AUTO qualification;
- S8-B rollback ownership;
- firewall rule construction;
- incident/detection/ML/MITRE/correlation behavior;
- S7 privacy controls;
- S10 deployment/runtime behavior.
