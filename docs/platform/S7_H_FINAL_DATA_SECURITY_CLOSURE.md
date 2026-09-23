# S7-H — Final Data Security & Privacy Closure

S7-H is the final closure gate for the AegisGuard Enterprise/SIEM S7
Data Security & Privacy workstream.

It does not introduce a new security architecture. It closes residual
diagnostic exposure found during the final merged-tree audit and records the
implemented S7 controls, boundaries, and remaining deployment responsibilities.

## Final residual fixes

The merged-tree audit found three collector diagnostic inconsistencies:

1. the live collector HTTP 5xx path printed Analyzer `response.text` directly;
2. the legacy collector startup banner printed the configured Analyzer URL
   without removing URL credentials, query parameters, or fragments;
3. the latest-Windows-RecordId probe printed raw PowerShell stdout before
   parsing it.

S7-H removes those exposures. Server response bodies pass through the existing
secret-safe HTTP sanitizer, displayed Analyzer URLs use the existing safe URL
projection, and the RecordId probe no longer prints raw stdout.

## S7 control matrix

| Slice | Control | Closure state |
| --- | --- | --- |
| S7-A | Data classification and central redaction primitives | Implemented |
| S7-B | SQLite secure-delete/temp-memory hardening and failed-payload retention lifecycle | Implemented |
| S7-C | Role-aware privacy projection for human SOC APIs | Implemented |
| S7-D | Explicit opt-in governance for legacy local raw-log output | Implemented |
| S7-E | Removal/prevention of tracked runtime raw-log artifacts | Implemented |
| S7-F | Secret-safe collector/analyzer diagnostics and durable error persistence | Implemented |
| S7-G | Privacy projection coverage for collector inventory and intelligence reads | Implemented |
| S7-H | Residual diagnostic closure and final regression gate | Implemented |

## Preserved forensic behavior

S7 does **not** destructively redact or delete canonical analyzer security
evidence merely to satisfy presentation privacy. Canonical evidence remains
available to the authorized SOC paths that require it. Privacy projection is
applied at lower-trust presentation/release boundaries instead.

Audit integrity and audit retention are not weakened by S7.

## Export/download boundary

At the S7-H audited integration baseline there is no active Flask
file-download/attachment endpoint using `send_file`, `send_from_directory`,
`as_attachment`, or `Content-Disposition`.

S7 therefore does not invent a speculative export implementation. A future
export/download feature must apply explicit authorization and privacy
projection before releasing evidence outside its canonical store.

## Repository hygiene boundary

Runtime raw/generated analyzer artifacts are not intended to be committed.
The S7 closure regression checks the known raw/generated artifact paths.

`backend/ML Aegis/ml/classified_logs.json` remains outside this S7 repository
hygiene removal because it is an ML-owned sample/dependency rather than the
collector runtime raw-output path.

Removing a file from the current Git snapshot does **not** remove copies from
historical Git commits. Any history rewrite is a separate repository-owner
operation requiring coordinated force-update/clone remediation.

## Storage guarantees and non-guarantees

S7-B SQLite PRAGMAs are defense-in-depth controls. They are **not** full
database encryption at rest.

Local raw-output permission handling is best-effort and cross-platform.
A POSIX-style mode such as `0600` is not a substitute for verified Windows
NTFS ACL policy.

Deployment-level encryption, disk protection, backup protection, key custody,
and operating-system ACL enforcement remain deployment responsibilities.

## Scope intentionally unchanged

S7-H does not change:

- collector authentication or mTLS trust;
- durable spool/retry/ACK semantics;
- detection, classification, correlation, MITRE, or ML behavior;
- incident lifecycle;
- canonical evidence semantics;
- audit-chain semantics;
- response authorization or response execution.

## Closure gate

S7 is considered technically closed when:

- S7-H focused tests pass;
- prior S7 focused tests pass;
- platform/intelligence/frontend/collector/analyzer regressions pass;
- `git diff --check` is clean;
- the final S7-H change is merged into `product/integration`.

Future features that add new release boundaries, exports, persistence stores,
or secret-bearing diagnostics must re-apply these controls rather than assume
S7 coverage automatically extends to new code.
