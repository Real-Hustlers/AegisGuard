# S12-B — Product / Deployment / SOC End-to-End Validation

## Purpose

S12-B validates the AegisGuard Enterprise product/deployment/SOC path without
duplicating Saran-owned backend/security E2E work.

Target product flow:

```text
Enterprise Package
    ↓
Install
    ↓
Analyzer Starts
    ↓
Collector Starts
    ↓
Collector Connects Securely
    ↓
Security Activity Arrives
    ↓
Intelligence API
    ↓
SOC Dashboard
    ↓
Incident Workspace
    ↓
MITRE / Evidence
    ↓
Response Governance UI
    ↓
Health / Audit Visibility
```

## GitHub-verified starting state

S12-B was initially created from the S11-D integration point and was rebased
before final validation after Saran-owned S12-A and S14 merged.

Current validation base:

- upstream branch: `Real-Hustlers/AegisGuard:product/integration`
- integration SHA: `5831b4fd2f3c95cde21cd1e6135e1e7687d17b86`
- S11-D PR: `#120`, merged
- S12-A PR: `#121`, merged
- S14 PR: `#122`, merged
- S16 security release sign-off PR: `#123`, merged
- prior release-document synchronization PR: `#117`, merged
- open PRs at the synchronization check: none observed

S12-A owns backend/security E2E validation. S14 owns enterprise backup and
recovery. S12-B consumes those merged contracts only where necessary to prove
the product/deployment/SOC path and does not duplicate their security
conclusions.

The existing release-facing documents predate the final S11-B/S11-C/S11-D,
S12-A, and S14 merges. Final synchronization belongs to S16, not this S12-B
validation slice.

## Scope boundary

S12-B owns product/deployment/SOC validation only.

It does not redefine:

- collector trust;
- authentication or authorization;
- incident security semantics;
- response authorization;
- backend security policy;
- backup/recovery policy;
- cryptographic trust;
- Saran-owned S12-A or S14 work.

If validation exposes a shared security-contract defect, stop and coordinate
before changing that contract.

## Automated product-contract validation

The S12-B automated test file verifies the cross-slice product contract:

```text
tests/e2e/test_s12_product_e2e_contract.py
```

It validates:

1. the source-free Windows bundle contains the Analyzer, mTLS Analyzer,
   Collector, S14 recovery executable, installer, launch, upgrade, and
   rollback artifacts;
2. packaged deployment keeps binaries under Program Files and writable state
   under ProgramData;
3. installed launch paths do not require Python/source execution;
4. the SOC dashboard consumes the real product API endpoints;
5. incident/MITRE/ML/governed-response state is represented in the UI;
6. SIMULATED and EXECUTED response states remain visually distinct;
7. loading, empty, stale, degraded, and error states are explicit;
8. collector credential/certificate fingerprints are not rendered;
9. bundle policy excludes Python source, databases, key/certificate material,
   and customer/runtime state;
10. upgrade and rollback preserve ProgramData runtime state;
11. responsive and keyboard-accessibility contracts remain present.

These tests are product-contract evidence. They do **not** by themselves prove a
real clean Windows installation.

## Product integration defect found during S12-B

The clean source-free package exposed a deployment usability gap before final
installed-product validation:

- application APIs require an authenticated AegisGuard user;
- the secure local provisioning implementation already exists in
  `backend/analyzer/user_admin.py`;
- the source-free Windows bundle did not package that operator CLI;
- therefore a clean deployment could not create its first application user
  without a Python/source checkout.

S12-B fixes only the packaging/deployment path by packaging
`AegisGuardUserAdmin.exe` from the existing CLI. Authentication, RBAC, session,
password hashing, and authorization semantics remain unchanged.

### Loopback UI session compatibility

Installed-product validation found a second deployment integration issue.
Authentication itself succeeded, but the packaged human UI runs on
loopback-only HTTP while application authentication defaults to a Secure
session cookie. The cookie was therefore not returned on subsequent HTTP API
requests and authenticated SOC reads failed.

The correction is deployment-scoped: `run_analyzer_ui.ps1` explicitly sets
`AEGISGUARD_SESSION_COOKIE_SECURE=false` only for this loopback-only HTTP
listener. The authentication implementation and its default
`cookie_secure=True` behavior remain unchanged for other deployment
boundaries.

## Required Windows installation evidence

A final S12-B PASS requires real operator-executed Windows evidence from the
built source-free bundle.

Record the actual values below. Do not fill them from assumptions.

| Evidence | Required result | Recorded result |
|---|---|---|
| Base integration SHA | Exact commit used to build | `5831b4fd2f3c95cde21cd1e6135e1e7687d17b86` |
| Bundle archive | Source-free Windows ZIP | `AegisGuard-Windows-Enterprise.zip` |
| Bundle SHA-256 | 64-hex digest | `70DCB7CB28024E8D985C9DD9828D597E95E53C942D8DAF8E4305485BC48B49BD` |
| Manifest source commit | Matches trusted source commit | `428fb376b469a6525ed4a048818595232b6ede4e` |
| Bundle verifier | PASS | `PASS`; archive pin and source-commit pin verified |
| Program Files Analyzer path | Present | `C:\Program Files\AegisGuard\S12B\Analyzer`; present |
| Program Files Collector path | Present | `C:\Program Files\AegisGuard\S12B\Collector`; present |
| ProgramData Analyzer path | Present | `C:\ProgramData\AegisGuard\S12B\Analyzer`; present |
| ProgramData Collector path | Present | `C:\ProgramData\AegisGuard\S12B\Collector`; present |
| Analyzer startup | Starts from installed package | `PASS`; installed UI and mTLS tasks started |
| Collector startup | Starts from installed package | `PASS`; installed scheduled task started |
| Python/source checkout required | No | `No`; installed packaged binaries/scripts used |
| `/healthz` | Healthy | `HTTP 200` |
| `/readyz` | Ready when dependencies are healthy | `HTTP 200`; database and data-directory checks healthy |
| UI load | Installed product UI loads | `HTTP 200` from installed loopback UI |
| Initial administrator provisioning | Source-free CLI; password not on command line | `PASS`; packaged UserAdmin CLI with prompted password |
| Collector inventory | Real server-authoritative data renders | `1`; ENROLLED, CURRENT, HEALTHY, mTLS verified |
| Intelligence snapshot | Real API response renders | `180` real Windows Security events analyzed |
| Incident workspace | Real incident data renders | `0 incidents`; authenticated real empty state |
| MITRE | Structured mapping visible when present | `0 mappings`; honest empty state because no findings were produced |
| Governed ML | Runtime/model identity visible when available | `UNAVAILABLE`; no promoted model installed |
| Response governance | State understandable | `0 actions`; authenticated real empty state; no live mutation performed |
| SIMULATED vs EXECUTED | Unambiguous | `PASS` via frontend contract; no live action manufactured |
| Empty/error state | Does not fake telemetry success | `PASS`; empty product states remain explicit |
| Restart | Required state survives | `PASS`; collector identity and protected credential survived scheduled-task restart |
| Upgrade/reinstall | ProgramData state preserved as supported | `PASS`; ProgramData database and existing administrator survived reinstall |
| Sensitive release scan | No forbidden material | `PASS`; source, databases, keys/certificates, logs, and runtime state excluded from bundle |
| Supported widths | Usable | `PASS` via frontend regression; no screenshot claim |

## Recorded installed-product evidence

Windows installed-product validation was performed from the source-free
bundle built from commit
`428fb376b469a6525ed4a048818595232b6ede4e`, based on integration
`5831b4fd2f3c95cde21cd1e6135e1e7687d17b86`.

The verified archive SHA-256 was
`70DCB7CB28024E8D985C9DD9828D597E95E53C942D8DAF8E4305485BC48B49BD`.
The bundle verifier confirmed both the archive pin and source-commit pin.

The packaged Analyzer UI, mTLS Analyzer, Collector, Recovery utility, and
UserAdmin utility were exercised without requiring a Python runtime or source
checkout at the installed-product boundary.

The source-free administrator account survived reinstall through preserved
ProgramData state. After reinstall, authenticated API access succeeded.

A real Windows Collector enrolled through the mTLS boundary and remained
ENROLLED, CURRENT, and HEALTHY. Server-observed mTLS verification succeeded.
After the temporary one-time enrollment bootstrap was removed, the normal
SYSTEM scheduled tasks restarted successfully and reused the protected
collector credential.

The live Collector checkpoint advanced from `4179545` to `4179824`.
The Analyzer processed 26 collector batches with zero failed batches and the
Intelligence API analyzed 180 real Windows Security events.

The validation activity produced no incident, MITRE, rule, correlation, or
governed-ML findings. These are recorded as real empty states rather than
manufactured detections. Governed ML reported `UNAVAILABLE` because no
promoted model was installed.

No live response mutation was performed. Response-action state remained
empty, while SIMULATED versus EXECUTED presentation semantics remain covered
by the frontend regression contract.

The installed `/healthz` and `/readyz` endpoints both returned HTTP 200.
The UI, mTLS Analyzer, and Collector scheduled tasks were simultaneously
RUNNING during the final product check.

## Evidence collection commands

Run from a clean S12-B branch after building the five Windows executables
required by the current merged bundle contract.

```text
.\.venv\Scripts\python.exe -m PyInstaller app.spec
.\.venv\Scripts\python.exe -m PyInstaller backend\analyzer\AegisGuardAnalyzerMTLS.spec
.\.venv\Scripts\python.exe -m PyInstaller backend\collector\AegisGuardCollector.spec
.\.venv\Scripts\python.exe -m PyInstaller backend\deployment\AegisGuardRecovery.spec
.\.venv\Scripts\python.exe -m PyInstaller backend\deployment\AegisGuardUserAdmin.spec
.\.venv\Scripts\python.exe scripts\validate_windows_deployment.py
.\.venv\Scripts\python.exe scripts\build_windows_offline_bundle.py --output-dir release
.\.venv\Scripts\python.exe scripts\verify_windows_offline_bundle.py release\AegisGuard-Windows-Enterprise.zip
Get-FileHash release\AegisGuard-Windows-Enterprise.zip -Algorithm SHA256
```

After installing the bundle on the Windows validation host, record:

```text
Get-ChildItem "$env:ProgramFiles\AegisGuard" -Recurse
Get-ChildItem "$env:ProgramData\AegisGuard" -Recurse
Get-ScheduledTask -TaskName "AegisGuard*"
```

Health/readiness evidence:

```text
Invoke-WebRequest http://127.0.0.1:5000/healthz -UseBasicParsing
Invoke-WebRequest http://127.0.0.1:5000/readyz -UseBasicParsing
```

Use the actual configured Analyzer UI URL if it differs from the default local
development URL.

Authenticated SOC API evidence must be collected through the supported login
and authorization flow. Do not bypass RBAC or CSRF to manufacture evidence.

## Screenshot evidence

Screenshots are useful for:

- installed SOC dashboard;
- Asset & Collector Management;
- Intelligence workspace;
- Incident workspace with MITRE evidence;
- governed ML status/version;
- response-governance state;
- SIMULATED and EXECUTED distinction;
- explicit degraded/empty state;
- supported narrow-width layout.

No screenshot is considered evidence until it is captured from the real
installed validation build.

## Test gate

Run:

```text
.\.venv\Scripts\python.exe -m pytest tests\e2e -q
.\.venv\Scripts\python.exe -m pytest tests\deployment -q
.\.venv\Scripts\python.exe -m pytest tests\frontend -q
.\.venv\Scripts\python.exe -m pytest tests\platform -q
.\.venv\Scripts\python.exe -m pytest tests\intelligence -q
.\.venv\Scripts\python.exe -m pytest backend\collector\test_live_monitoring.py -q
.\.venv\Scripts\python.exe -m pytest backend\analyzer\test -q
git diff --check
```

## Exit criteria

S12-B is ready for PR only when:

1. automated product-contract validation passes;
2. existing deployment/frontend/platform/intelligence regressions pass;
3. real bundle hash and manifest evidence are recorded;
4. clean installed Analyzer and Collector startup are proven;
5. the installed UI is shown consuming real backend data;
6. restart/state-preservation evidence is recorded;
7. no sensitive/runtime material is present in the release;
8. known limitations are documented without overstating production guarantees;
9. the working tree contains only S12-B product/deployment validation changes.

S12-B must not be marked complete from static tests alone.
