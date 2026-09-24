# S8-E — Approval Context Binding

S8-E binds a pending response action to the execution-relevant policy under
which it was created.

## Problem closed

S8-D established independent approval, but a pending action could outlive a
response-policy change.

Before S8-E:

1. an action could be requested while SOAR was enabled;
2. an administrator could later set `soar_mode=OFF`;
3. the old pending action could still be approved because `approve()` did not
   enforce the current response mode.

Similarly, a request created while `soar_dry_run=true` could later be approved
after that setting changed to `false`, silently converting a simulation-intended
approval into live firewall execution.

This is a time-of-check/time-of-use governance gap.

## S8-E invariant

Every newly created `PENDING_APPROVAL` action stores an `approval_context` in
response-action metadata.

For MANUAL mode the context contains:

```text
version
mode
dry_run
```

For AUTO mode it additionally contains:

```text
auto_min_score
```

At approval time the engine compares the current execution-relevant context with
the stored context.

If it changed, approval is denied and the action remains pending.

## OFF is a kill switch

If current SOAR mode is `OFF`, approval is denied immediately:

```text
error = response_mode_off
status remains PENDING_APPROVAL
firewall mutation = none
```

This applies even when the request was valid when originally created.

## Policy drift

Changing any approval-bound execution setting invalidates the pending approval:

```text
MANUAL → AUTO
AUTO → MANUAL
dry_run true → false
dry_run false → true
AUTO threshold change
```

The denial code is:

```text
response_policy_changed
```

The operator must review the action under the current policy rather than relying
on approval intent formed under different execution semantics.

## Existing pending actions

A pending action created before S8-E does not contain an approval context.
Such an action fails closed with:

```text
approval_context_missing
```

It is not executed.

## Target safety remains current

S8-E does not freeze target-safety policy.

At approval time AegisGuard still revalidates the target against the current:

- allowlist;
- Analyzer/Collector self-address protection;
- private-address blocking policy;
- reserved/loopback/multicast protections.

This means newly restrictive target policy continues to stop execution.

## Audit

The existing S8-D approval API maps governance denials to HTTP 403. Existing
sensitive-operation auditing therefore records these S8-E failures as denied
`RESPONSE.APPROVE` operations with the stable error code in audit details.

## Boundaries preserved

S8-E does not change:

- S8-D maker/checker separation;
- S8-C AUTO qualification criteria;
- S8-B rollback ownership;
- firewall rule construction;
- incident/detection/ML/MITRE/correlation behavior;
- S7 privacy controls;
- S10 deployment/runtime behavior.
