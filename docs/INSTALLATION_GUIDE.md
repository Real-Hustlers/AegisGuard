# AegisGuard Enterprise Installation Guide

## Release

Product: AegisGuard Enterprise

Version: v0.1.0 Release Candidate

## Scope

This guide describes the validated source-free Windows deployment path for the
v0.1.0 Release Candidate.

A deployed host does not require a Python runtime or repository checkout to run
the packaged Analyzer, mTLS Analyzer, Collector, Recovery utility, or UserAdmin
utility.

## Package contents

The Windows enterprise bundle contains:

- `AegisGuardAnalyzer.exe`
- `AegisGuardAnalyzerMTLS.exe`
- `AegisGuardCollector.exe`
- `AegisGuardRecovery.exe`
- `AegisGuardUserAdmin.exe`
- Windows installation and runtime scripts
- upgrade and rollback scripts
- bundle manifest and SHA-256 checksums

The bundle intentionally excludes:

- runtime databases
- customer logs
- Collector credentials
- enrollment or recovery tokens
- private keys
- certificates
- Python source

## Deployment layout

Installed binaries belong under:

`%ProgramFiles%\AegisGuard\`

Mutable runtime data belongs under:

`%ProgramData%\AegisGuard\`

Do not place runtime databases, Collector state, credentials, or private keys
under Program Files.

## Analyzer UI installation

Use the packaged Analyzer UI installer with the packaged Analyzer executable.

The validated local human UI is loopback-only HTTP. The deployment runner
applies the loopback-specific session-cookie setting required for this local
boundary. The application authentication default remains secure for other
deployment boundaries.

## Initial administrator provisioning

Use the packaged:

`AegisGuardUserAdmin.exe`

The password is prompted interactively and is not accepted as a command-line
argument.

For the default Analyzer data location, an elevated operator can provision an
administrator with:

`AegisGuardUserAdmin.exe <username> --role ADMINISTRATOR`

## Collector-facing mTLS Analyzer

The Collector-facing Analyzer listener is provided by:

`AegisGuardAnalyzerMTLS.exe`

Deploy TLS material separately under protected ProgramData storage.

The release bundle does not contain production certificates or private keys.

## Collector installation

The packaged Collector requires:

- an HTTPS Analyzer endpoint;
- CA trust material;
- a client certificate;
- a client private key;
- one-time governed enrollment bootstrap.

Enrollment and recovery bootstrap tokens are not persisted in the packaged
Collector configuration.

The Collector uses the existing authenticated durable-ingest protocol with
mTLS.

## Verification

After installation verify:

- Analyzer UI task is running;
- mTLS Analyzer task is running;
- Collector task is running;
- `/healthz` returns HTTP 200;
- `/readyz` returns HTTP 200;
- Collector inventory shows the expected enrolled Collector;
- Collector transport is healthy;
- server-observed mTLS verification succeeds;
- SOC APIs require authenticated access.

## Upgrade and rollback

Use the packaged enterprise upgrade and rollback scripts.

Mutable ProgramData state is preserved by the supported upgrade/reinstall path.

Do not replace ProgramData with release-media contents.

## Air-gapped use

The validated deployment path does not require an external cloud dependency for
normal local operation.

Required installation media, certificates, trust material, and release pins
must be provisioned through the organization's controlled offline process.

## Boundaries

The v0.1.0 Release Candidate does not claim:

- publisher code-signing or non-repudiation;
- managed cloud orchestration;
- arbitrary distributed Analyzer clustering;
- automatic remote backup replication;
- HSM/key escrow;
- automatic backup-storage encryption.
