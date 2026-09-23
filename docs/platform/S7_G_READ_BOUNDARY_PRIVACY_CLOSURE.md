# S7-G — Human Read-Boundary Privacy Closure

S7-G closes the remaining role-aware privacy gaps on authenticated,
human-facing read APIs.

## Newly covered read surfaces

The existing S7 privacy projection now covers:

- `/api/collectors`
- `/api/intelligence`

These routes remain readable according to the existing S4 RBAC policy. S7-G
does not change who may access them; it changes only the response projection
for lower-trust roles.

## Role behavior

- `ADMINISTRATOR` and `ANALYST` retain operational SOC telemetry while
  secret-bearing fields are still redacted.
- `VIEWER` receives a lower-trust projection where security-sensitive
  endpoint/user/evidence fields are redacted.
- Unlisted APIs are not implicitly altered.

## Classification alias

S7-G additionally classifies `raw_event` as security-sensitive. `peer_ip` was
already classified security-sensitive on the audited integration baseline.

This aligns intelligence evidence with the existing classification of
`raw_log`, hostname, user, process, file path, and network-address fields.

## Audit boundary

`/api/audit/*` is already administrator-only under the application
authorization policy, so S7-G does not add viewer projection to that surface.

## Export/download boundary

The audited application has no active HTTP file-download/export route using
Flask file/attachment primitives. S7-G therefore does not introduce a
speculative export feature; any future export surface must apply authorization
and S7 privacy projection before release.

## Scope

S7-G does not change collector/device trust, authentication, RBAC decisions,
detection, ML, correlation, MITRE mappings, incident lifecycle, audit
integrity, persistence, or response execution.
