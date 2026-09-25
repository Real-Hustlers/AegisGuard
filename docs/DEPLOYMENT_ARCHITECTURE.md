# AegisGuard Enterprise Deployment Architecture

## Release

Version: v0.1.0 Release Candidate

## Validated Windows deployment

The release-candidate deployment separates packaged executables from mutable
runtime state.

Windows Host
|
+-- Program Files
|   |
|   +-- Analyzer UI
|   +-- mTLS Analyzer
|   +-- Collector
|   +-- Recovery utility
|   +-- UserAdmin utility
|
+-- ProgramData
    |
    +-- Analyzer database/state
    +-- governed ML registry
    +-- Collector configuration/state
    +-- protected TLS material

## Product data flow

Windows Security Events
        |
        v
Packaged Collector
        |
        | HTTPS + mTLS
        v
Collector-facing Analyzer
        |
        v
Durable Analyzer State
        |
        +--------------------+
        |                    |
        v                    v
Detection / Intelligence   Incident / Response Governance
        |                    |
        +----------+---------+
                   |
                   v
            Authenticated SOC UI

## Human UI boundary

The validated local human UI is loopback-only.

The UI consumes authenticated product APIs for:

- events;
- alerts;
- Collector inventory;
- intelligence;
- incidents;
- response actions;
- operational health.

## Collector trust boundary

Collector transport uses:

- authenticated enrollment;
- per-Collector credential state;
- mTLS certificate verification;
- server-derived Collector liveness;
- durable ingest acknowledgement.

Collector-reported operational state is not treated as the sole security
authority.

## Air-gapped deployment

Normal local operation can run without an external cloud dependency.

Air-gapped deployment requires controlled local provisioning of:

- release media;
- trusted release hashes/pins;
- certificates and CA material;
- one-time enrollment bootstrap;
- backup media.

## Multiple Collectors

The platform supports Collector identities and centralized Analyzer inventory.

Actual capacity depends on event rate and hardware and must be benchmarked for
the target environment.

## Not claimed by this release candidate

The v0.1.0 Release Candidate does not claim:

- arbitrary distributed Analyzer clustering;
- managed cloud orchestration;
- remote-remediation orchestration across arbitrary third-party products;
- remote backup replication;
- publisher-signature non-repudiation.

## Runtime state

Mutable runtime state remains under ProgramData and is preserved by the
supported upgrade/reinstall path.

Release bundles must not contain customer logs, runtime databases, private keys,
production certificates, or Collector credentials.
