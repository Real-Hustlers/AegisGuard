# S10-D — Windows Collector Installed Runtime Validation

## Status

S10-D is verified on Windows using the packaged AegisGuard Collector,
the enterprise Collector installer, Program Files / ProgramData separation,
and a SYSTEM scheduled task.

Validation date: 2026-09-23

## Scope

This phase validates deployment/runtime behavior only.

It does not change:

- collector authentication semantics
- mTLS trust or certificate verification
- enrollment or recovery-token semantics
- device credential protection
- incident lifecycle
- human RBAC
- audit integrity
- response authorization or execution

## Installed layout

Validated binary layout:

```text
%ProgramFiles%\AegisGuard\S10DValidation\Collector\
├── AegisGuardCollector.exe
└── run_collector.ps1

Validated mutable runtime layout:

%ProgramData%\AegisGuard\S10DValidation\Collector\
├── config.json
└── collector_state.db

Local raw security-log persistence remained disabled.

Installer security behavior

The Collector installer was verified to:

require an HTTPS Analyzer base URL
configure authenticated Collector transport
require Collector mTLS
write Collector runtime configuration outside Program Files
register the startup task as SYSTEM with Highest run level
install the startup task disabled by default
avoid persisting enrollment bootstrap tokens
avoid persisting recovery bootstrap tokens
keep raw_output_enabled=false

The scheduled-task command line contained filesystem paths only and did not
contain enrollment or recovery bootstrap secrets.

Packaged-runtime defect discovered

The first installed-runtime validation failed before durable-state
initialization with:

AttributeError: module 'platform' has no attribute 'node'

The Collector PyInstaller specification exposed:

PROJECT_ROOT/backend

as a top-level module search path.

Because AegisGuard contains:

backend/platform/

that search path allowed the project package to shadow Python's standard
library platform module in the frozen Collector.

The packaged Collector therefore resolved import platform incorrectly.

Fix

The Collector PyInstaller search path was reduced to:

PROJECT_ROOT

Imports such as backend.collector.* and backend.platform.* remain
available through the repository root, while backend/platform can no
longer masquerade as the standard-library platform module.

A deployment regression test now prevents
str(PROJECT_ROOT / "backend") from returning to the Collector spec.

Rebuilt packaged Collector

The corrected Collector executable rebuilt successfully with PyInstaller
6.22.3 on Python 3.11.15.

Validated rebuilt artifact:

AegisGuardCollector.exe
size: 13,951,271 bytes

The packaged artifact scan found no bundled:

private keys
PEM files
PFX/P12 files
certificates
SQLite databases
collector runtime databases
Real installed-runtime proof

After rebuilding and reinstalling the corrected package:

the packaged Collector remained running
collector_state.db was created under ProgramData
local raw-output JSON remained absent
the SYSTEM startup task remained running
the packaged Collector processes executed from Program Files

Task Scheduler reported:

State: Running
LastTaskResult: 267009

267009 is the Windows Task Scheduler running-state result while the
long-running Collector task remains active.

Upgrade preservation proof

Before reinstalling over the existing deployment, the Collector state
database and packaged executable were hashed.

Observed state SHA-256 before reinstall:

E116003F096C6FE40F38FC827F9E993B893867FBD8AF64D1E108C4F07E224357

Observed packaged executable SHA-256:

2363B5C072722840215DE7644259659168469B540E56E8789A7212A35663CAAE

Observed Collector identity:

a11eff3d-6825-4c41-ad56-2a7ae2f6fc70

After reinstalling into the same Program Files and ProgramData locations:

StateFilePreserved             True
CollectorIdentityPreserved     True
InstalledBinaryMatchesBuild    True
RawOutputStillAbsent           True
Restart-continuity proof

The SYSTEM scheduled task was started again after reinstall.

The Collector remained running from:

C:\Program Files\AegisGuard\S10DValidation\Collector\AegisGuardCollector.exe

The Collector identity after restart matched the pre-upgrade identity:

True

This verifies that restart and reinstall do not silently generate a new
Collector identity or replace the durable state database.

Packaging operational note

PyInstaller warned that future PyInstaller 7.0 releases will reject running
the build itself from an elevated administrator terminal.

Therefore:

package/build operations should run in a normal development shell
installation and SYSTEM scheduled-task validation should run in an
elevated administrator shell
S10-D conclusion

S10-D verifies the packaged Windows Collector across:

build
  -> install
  -> Program Files / ProgramData separation
  -> SYSTEM task registration
  -> packaged startup
  -> durable state creation
  -> stop
  -> reinstall / upgrade
  -> state preservation
  -> restart
  -> Collector identity continuity

No authentication, mTLS, credential, RBAC, incident, audit, or response
security boundary was weakened to obtain this result.
