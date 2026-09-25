# AegisGuard Enterprise Administrator Guide

## Release

Version: v0.1.0 Release Candidate

## Scope

This guide covers administration of the AegisGuard Enterprise v0.1.0 Release
Candidate.

## Administrator responsibilities

Administrators are responsible for:

- installation and scheduled-task management;
- local application-user provisioning;
- Collector onboarding;
- TLS and certificate material;
- operational health;
- backup and recovery;
- release verification;
- governed configuration changes.

## User provisioning

Use the packaged `AegisGuardUserAdmin.exe` utility for source-free local user
provisioning.

Passwords are entered interactively and are not accepted as command-line
arguments.

Supported application roles include:

- `ADMINISTRATOR`
- `ANALYST`
- `VIEWER`

## Installed components

The Windows enterprise package contains:

- `AegisGuardAnalyzer.exe`
- `AegisGuardAnalyzerMTLS.exe`
- `AegisGuardCollector.exe`
- `AegisGuardRecovery.exe`
- `AegisGuardUserAdmin.exe`

Installed binaries belong under `%ProgramFiles%\AegisGuard\`.

Mutable runtime state belongs under `%ProgramData%\AegisGuard\`.

## Service and health checks

Verify the installed scheduled tasks for:

- Analyzer UI;
- mTLS Analyzer;
- Collector.

Verify:

- `/healthz`;
- `/readyz`;
- Collector inventory;
- Collector liveness;
- Collector transport status;
- server-observed mTLS verification.

## Collector onboarding

Collector onboarding uses the existing authenticated Collector protocol.

Administrators must provide:

- Analyzer HTTPS endpoint;
- CA trust material;
- Collector client certificate;
- Collector private key;
- governed one-time enrollment bootstrap.

Enrollment and recovery tokens must not be persisted in release media or
ordinary Collector configuration.

## TLS material

Production certificates and private keys are runtime deployment material.

They are intentionally excluded from the source-free release bundle and from
portable S14 backup media.

TLS material must be protected using organization-approved deployment and
credential procedures.

## Governed ML

Governed ML availability is visible through the product.

If no promoted model is installed, `UNAVAILABLE` is an expected runtime state.

Do not manufacture ML findings when no promoted model exists.

## Response governance

Response workflows preserve the existing:

- role-based authorization;
- approval requirements;
- separation of duties;
- simulation/dry-run semantics;
- audit attribution;
- retry/reconciliation and rollback governance where supported.

`SIMULATED` does not mean a live response was executed.

## Backup and recovery

Use the packaged `AegisGuardRecovery.exe` utility and the existing S14 recovery
documentation.

Portable recovery data intentionally excludes Collector credentials,
TLS/private-key material, transient human sessions, and queued customer-event
payloads.

Excluded credentials and TLS material must be re-provisioned through governed
procedures after recovery.

## Release verification

Before deployment:

1. verify the trusted archive SHA-256;
2. verify the expected source-commit pin;
3. verify bundle checksums and manifest coverage;
4. verify the bundle reports `source_dirty=false`;
5. confirm no runtime database, customer logs, production certificates, or
   private keys are present in the release media.

Trusted SHA-256 and source-commit pins do not constitute publisher-signature
non-repudiation.

## Troubleshooting

Check:

1. scheduled-task state;
2. `/healthz`;
3. `/readyz`;
4. Analyzer ProgramData access;
5. Collector ProgramData access;
6. Collector liveness and transport state;
7. certificate trust and mTLS configuration;
8. authenticated UI session state;
9. available storage.

Do not expose passwords, CSRF tokens, session tokens, enrollment/recovery
tokens, Collector credentials, or private-key contents in support evidence.

## Release boundaries

The v0.1.0 Release Candidate does not claim:

- managed cloud orchestration;
- arbitrary distributed Analyzer clustering;
- remote backup replication;
- HSM/key escrow;
- automatic backup-storage encryption;
- publisher-signature non-repudiation.
