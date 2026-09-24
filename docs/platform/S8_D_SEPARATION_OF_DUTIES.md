# S8-D — Separation of Duties

S8-D adds maker/checker separation to response approval.

The governed response path remains:

```text
REQUEST / RECOMMEND
→ PENDING_APPROVAL
→ INDEPENDENT APPROVAL
→ DRY_RUN or CONTROLLED EXECUTION
```

## Problem closed

S8-A established an explicit approval endpoint and trusted requester/approver
identity fields. S8-C ensured that only `approve()` can enter controlled block
execution.

Before S8-D, however, the same authenticated administrator could create a
response request and approve that same request. Direct engine callers could
also call `approve()` without an approver identity.

That made approval explicit but not independent.

## S8-D invariant

For every `PENDING_APPROVAL` action:

- `approved_by_user_id` must be present;
- if `requested_by_user_id` is present, the approver must be a different user;
- a denied approval does not change response-action state;
- a denied approval does not call the firewall adapter.

Human request:

```text
administrator A requests
→ PENDING_APPROVAL
→ administrator A approval: DENIED
→ administrator B approval: permitted
```

System-generated AUTO recommendation:

```text
requested_by_user_id = null
→ administrator approval: permitted
```

AUTO recommendations do not have a human maker, so there is no requester identity
with which the approving administrator can conflict.

## HTTP behavior

`POST /api/response-actions/<id>/approve` remains administrator-only through
existing application RBAC and CSRF enforcement.

Governance denials return HTTP 403 with stable error codes:

- `approval_identity_required`
- `self_approval_forbidden`

The client cannot supply or override the approver identity. It is still derived
from the authenticated server-side session.

## Audit

Sensitive-operation audit classifies the denied operation as:

```text
action = RESPONSE.APPROVE
outcome = DENIED
```

The denial reason is stored in audit details. Passwords, session tokens, CSRF
tokens, and other secrets are not added to response-action metadata.

## Storage

No schema migration is required.

S8-D uses the existing fields:

- `requested_by_user_id`
- `approved_by_user_id`
- `approval_required`
- `updated_at`

## Boundaries preserved

S8-D does not change:

- S8-C AUTO qualification rules;
- S8-B rollback governance;
- target validation or allowlists;
- firewall rule construction;
- incident/detection/ML/MITRE/correlation behavior;
- S7 privacy controls;
- S10 deployment/runtime behavior.
