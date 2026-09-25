# S11-B — Trusted Release Pinning

## Purpose

S11-A verifies the internal integrity contract of the S10E Windows enterprise
offline bundle.

S11-B adds an independent acceptance boundary: an operator can require the ZIP
archive SHA-256 and/or source commit to match values obtained through a
separate trusted channel.

This prevents a modified bundle from being accepted merely because an attacker
also replaced the bundle's embedded manifest and checksum file.

## Verification command

Example:

```text
python scripts/verify_windows_offline_bundle.py AegisGuard-Windows-Enterprise.zip --expected-archive-sha256 <trusted-sha256> --expected-source-commit <trusted-commit>
```

The trusted values must come from outside the ZIP being verified.

## Controls

S11-B adds:

- strict 64-hex SHA-256 pin validation;
- strict 40-hex Git commit pin validation;
- fail-closed archive digest mismatch handling;
- fail-closed manifest source-commit mismatch handling;
- explicit output showing whether each external pin was verified;
- rejection of archive-digest pinning when only an extracted directory is
  supplied.

S11-A verification remains compatible when no external pins are supplied.

## Security boundary

Trusted release pinning is stronger than self-contained bundle checksums only
when the expected values are obtained through an independent trusted channel.

Examples include:

- a protected internal release record;
- an authenticated administrator handoff;
- a trusted source-control release record;
- a future signed release manifest.

S11-B does not claim digital publisher identity or non-repudiation.

It deliberately does not implement custom cryptography or invent a signing
format. A future signing slice should use a standard, reviewed signing
primitive and explicit key-custody lifecycle.

## Scope unchanged

S11-B does not modify:

- Analyzer runtime;
- Collector runtime;
- database schemas;
- S3 collector/device trust;
- S7 data-security/privacy controls;
- S8 response governance;
- S9 operational visibility;
- S10 installation ownership.

## Validation gate

```text
python -m pytest tests/deployment/test_s11b_release_pinning.py -q
python -m pytest tests/deployment -q
python -m pytest tests/platform -q
python -m pytest tests/intelligence -q
python -m pytest tests/frontend -q
python -m pytest backend/collector/test_live_monitoring.py -q
python -m pytest backend/analyzer/test -q
git diff --check
```
