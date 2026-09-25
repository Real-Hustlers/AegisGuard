# AegisGuard Enterprise System Requirements

## Release

Version: v0.1.0 Release Candidate

## Supported validated deployment

The current release-candidate validation covers source-free Windows deployment
of the packaged Analyzer, mTLS Analyzer, Collector, Recovery utility, and
UserAdmin utility.

The installed product does not require Python or a source checkout.

Development and build environments do require Python and the repository
toolchain.

## Operating system

Validated release packaging target:

- Windows x86_64

Other operating systems are not claimed as part of the validated v0.1.0
source-free release package.

## Hardware guidance

Capacity depends on:

- event rate;
- number of Collectors;
- retention requirements;
- database growth;
- enabled detection workload;
- governed ML availability and model size.

### Small validation environment

Suggested starting point:

- CPU: 4 cores
- RAM: 8 GB
- Storage: 100 GB SSD

### SOC deployment

Suggested starting point:

- CPU: 8 to 16 cores
- RAM: 32 GB
- Storage: 500 GB SSD or larger

These are planning baselines, not fixed capacity guarantees. Benchmark the
target workload before production sizing.

## Storage

Use persistent storage for Analyzer and Collector ProgramData.

Storage planning should include:

- Analyzer database growth;
- Collector durable state;
- retention requirements;
- backup copies;
- governed ML registry data;
- operational headroom.

Portable release media must remain separate from runtime/customer data.

## Network

Required communication depends on topology.

Collector-to-Analyzer communication uses HTTPS with mTLS for the validated
authenticated deployment path.

The local human UI validation path binds to loopback.

Air-gapped deployments can operate without external Internet connectivity when
all required installation media and trust material are provisioned locally.

## Security prerequisites

Operators must provide and protect:

- administrator access to install scheduled tasks;
- CA trust material;
- server certificate and private key;
- Collector client certificate and private key;
- governed one-time enrollment bootstrap;
- backup media appropriate to organizational policy.

Release media intentionally excludes production TLS/private-key material and
Collector credentials.

## Machine learning

Governed ML is optional at runtime.

If no promoted model is installed, the product reports the governed ML runtime
as unavailable rather than fabricating ML findings.

Hardware requirements for future promoted local models depend on model size and
runtime requirements and must be evaluated separately.

## Deployment boundaries

The v0.1.0 Release Candidate does not validate arbitrary Analyzer clustering,
managed cloud orchestration, remote backup replication, or HSM-backed key
custody.
