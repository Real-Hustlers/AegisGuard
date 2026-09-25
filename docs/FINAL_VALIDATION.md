# AegisGuard Enterprise v0.1.0 Release-Candidate Final Validation

## Release identity

Product: AegisGuard Enterprise

Version: v0.1.0

Release stage: Release Candidate

Integration baseline before S16 release preparation:

`f4fc3cb17281d12453457d19fc078f9812a303dc`

Artifact source commit:

`05475d9cb655db070cba8dbe9035e6e656409fcd`

## Merged prerequisites

The release-candidate baseline includes:

- S12-A backend/security E2E validation — PR #121;
- S14 backup/recovery closure — PR #122;
- S16 enterprise security release sign-off — PR #123;
- S12-B product/deployment/SOC validation — PR #124.

The security conclusions recorded in `docs/SECURITY_RELEASE_SIGNOFF.md` remain
authoritative and are not replaced by this document.

## Final regression evidence

Final regression validation for S16 release preparation recorded:

- complete `tests` tree: `624 passed, 23 subtests passed in 66.59s`;
- Analyzer regression: `37 passed, 10 subtests passed in 6.47s`;
- live Collector regression: `8 passed in 0.20s`;
- Windows deployment preflight: `PASS`;
- required deployment files: `22`;
- deployment issues: `0`;
- `git diff --check`: `PASS`.

## S12-B installed-product evidence

Merged S12-B installed-product validation established:

- source-free Windows Analyzer UI;
- source-free mTLS Analyzer;
- source-free Collector;
- source-free Recovery utility;
- source-free UserAdmin utility;
- Program Files / ProgramData separation;
- source-free administrator provisioning;
- authenticated UI access after reinstall;
- real Collector enrollment through mTLS;
- stable Collector identity after restart;
- protected Collector credential continuity under SYSTEM;
- Collector state `ENROLLED`;
- liveness `CURRENT`;
- transport `HEALTHY`;
- server-observed mTLS verification;
- Collector checkpoint advancement from `4179545` to `4179824`;
- `26` processed Collector batches;
- `0` failed Collector batches;
- `180` real Windows Security events analyzed;
- `/healthz` HTTP 200;
- `/readyz` HTTP 200.

The observed activity produced no incident, response action, MITRE mapping,
rule finding, correlation finding, or governed-ML finding.

These are recorded as honest empty states.

Governed ML reported `UNAVAILABLE` because no promoted model was installed.

No live response mutation was manufactured for release validation.

## Final Windows release-candidate artifact

Archive:

`AegisGuard-Windows-Enterprise.zip`

Artifact source commit:

`05475d9cb655db070cba8dbe9035e6e656409fcd`

Source dirty:

`False`

Payload file count:

`15`

Checksummed file count:

`16`

Archive SHA-256:

`C7DB8423AA7BF6A01F694F6F0D54B4B467AD827AE0D04F6B2EFCEAF7E1DB99D0`

Bundle verification:

`PASS`

Archive pin verification:

`True`

Source-commit pin verification:

`True`

The artifact source commit intentionally precedes this evidence-only
documentation update. The binary archive itself is not rebuilt by this
documentation-only evidence commit.

## Packaged executables

The final Windows release-candidate artifact contains:

- `AegisGuardAnalyzer.exe`
- `AegisGuardAnalyzerMTLS.exe`
- `AegisGuardCollector.exe`
- `AegisGuardRecovery.exe`
- `AegisGuardUserAdmin.exe`

## Package hygiene

Release media excludes:

- Python source;
- runtime SQLite databases;
- customer logs;
- Collector credentials;
- enrollment/recovery tokens;
- private keys;
- production certificates;
- mutable runtime state.

## Known boundaries

The v0.1.0 Release Candidate does not claim:

- publisher-signature non-repudiation;
- arbitrary distributed Analyzer clustering;
- managed cloud orchestration;
- remote backup replication;
- HSM/key escrow;
- automatic backup-storage encryption;
- arbitrary third-party response orchestration;
- reconstruction of Collector-local queued event bodies after Collector disk
  loss before delivery.

TLS/private-key material and Collector credentials remain external governed
runtime material.

## Publication boundary

Final Git tagging, GitHub Release creation, and external publication remain
maintainer/release-owner actions.

This validation does not authorize a self-merge or release tag.
