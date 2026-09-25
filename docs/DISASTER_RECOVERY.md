# AegisGuard Enterprise Disaster Recovery Procedure

## Objective

Recover AegisGuard Enterprise without silently weakening identity,
response-governance, or audit evidence.

## Healthy-system preparation

Maintain verified backups outside the live Analyzer runtime directory.

A backup is usable only when `AegisGuardRecovery.exe verify` succeeds and the
archive SHA-256 is recorded in the organization's protected backup inventory.

Backup storage protection and off-host replication are deployment/operator
responsibilities. S14 provides integrity verification but does not claim
publisher signatures or remote backup transport.

## Controlled recovery sequence

### 1. Confirm failure scope

Determine whether the failure affects:

- Analyzer ProgramData;
- Collector ProgramData;
- governed ML registry;
- installation binaries;
- TLS/private-key material.

Release binaries are recovered from the independently verified S11 release
bundle, not from an S14 state backup.

### 2. Stop AegisGuard services

Stop the Analyzer UI, Analyzer mTLS listener, and Collector before applying a
state restore.

Do not use `--services-stopped` while the services are still writing their
runtime databases.

### 3. Verify release media

Verify the Windows enterprise release bundle with the S11-A/S11-B controls
before reinstalling binaries.

### 4. Verify backup

Run:

```powershell
AegisGuardRecovery.exe verify --backup C:\ProgramData\AegisGuard\Backups\AegisGuard-enterprise-state.zip
```

Do not continue if integrity validation fails.

### 5. Inspect the restore plan

Run restore without `--apply`.

The tool verifies the backup and prints the component targets without
modifying the system.

### 6. Apply restore

With services stopped:

```powershell
AegisGuardRecovery.exe restore --backup C:\ProgramData\AegisGuard\Backups\AegisGuard-enterprise-state.zip --apply --services-stopped
```

The restore is transactional for the local targets.

### 7. Recover an interrupted restore if required

An apply operation records a restore transaction before target replacement.

If the process or host is interrupted while the transaction is in
`PREPARED` or `APPLYING`, use `recover-transaction` against that exact
transaction directory before attempting another restore.

### 8. Re-provision excluded security material

Portable S14 backups deliberately do not contain:

- Analyzer TLS private keys/certificates;
- Collector TLS private keys/certificates;
- enrollment tokens;
- recovery tokens;
- Collector device credentials.

Restore these through the existing certificate/credential deployment
procedures and protected secret channels.

The restored Collector ID and checkpoint remain available, so credential
recovery can retain device identity instead of creating an unrelated device.

### 9. Start Analyzer and verify

Start the Analyzer and verify:

- startup preflight passes;
- `/readyz` is ready;
- platform schema is current;
- audit chain is valid;
- incident records are present;
- response-governance records are present;
- Collector registry state is present.

### 10. Response-governance safety

Human sessions are intentionally not restored. Operators must authenticate
again.

Pending response actions retain their evidence and governance state. They do
not become pre-authorized by the restore.

Existing separation-of-duties checks still apply, including the prohibition on
self-approval.

Terminal actions remain terminal. A restore does not convert a historical
`DRY_RUN`, `EXECUTED`, `REJECTED`, `FAILED`, or rolled-back record into a new
execution request.

### 11. Recover interrupted ingestion

Analyzer durable batches that were captured in `PROCESSING` state are
re-queued by the existing Analyzer startup recovery function.

Event persistence remains idempotent, preventing duplicate event rows on the
replayed batch.

Collector-local queued event bodies are intentionally not exported into S14
portable backups. If the Collector disk itself was lost before those batches
reached the Analyzer, those locally queued events cannot be reconstructed from
the S14 backup.

### 12. Start Collector and verify

After certificate/private-key and credential recovery:

- start the Collector;
- verify the restored Collector ID;
- verify checkpoint continuity;
- verify authenticated heartbeat;
- verify mTLS;
- verify durable event delivery.

## Recovery acceptance criteria

Recovery is accepted only when:

- backup verification passes;
- Analyzer readiness passes;
- audit chain is valid;
- incidents are present;
- response-governance records are present and governed;
- Collector server-side identity is present;
- Collector local ID/checkpoint continuity is correct;
- no old human session is valid;
- transient Collector credentials were not copied from backup media;
- ML registry integrity validates when present;
- security processing remains available even if governed ML is degraded.

## Known boundary

S14 protects and restores AegisGuard application state. It does not implement
remote replication, storage encryption, HSM/key escrow, Windows certificate
backup, or organization-wide retention policy. Those controls belong to the
deployment environment and must be governed separately.
