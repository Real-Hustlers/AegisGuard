# AegisGuard Enterprise Product Overview

## Introduction

AegisGuard Enterprise is a security operations platform designed to help organizations monitor security events, identify threats, investigate incidents, and manage controlled responses.

---

# Security Operations Workflow
Security Events
|
v
Collection
|
v
Analysis Engine
|
v
Threat Detection
|
v
Incident Investigation
|
v
Governed Response
|
v
Audit

---

# Core Capabilities

## Detection

Analyzes security events and identifies suspicious activities using detection mechanisms.

## Machine Learning

Provides additional intelligence through ML-based analysis and prediction support.

## Investigation

Provides security analysts with incident context, evidence, and investigation information.

## Threat Intelligence

Maps security findings with MITRE ATT&CK techniques for better understanding.


## Operational Reliability

Provides read-only collector and asset visibility, server-derived liveness, health/readiness checks, and bounded administrator-only operational diagnostics.
## Response Governance

Provides controlled response workflows with authorization and audit tracking.

---

## Enterprise Windows Deployment

The v0.1.0 Release Candidate supports a source-free Windows deployment model
with packaged Analyzer UI, mTLS Analyzer, Collector, Recovery, and local
UserAdmin executables.

Installed binaries are separated from mutable runtime state:

- binaries under `%ProgramFiles%\AegisGuard\`;
- runtime data under `%ProgramData%\AegisGuard\`.

Collector-to-Analyzer transport uses the existing authenticated Collector
protocol with mTLS. Bootstrap enrollment secrets are not stored in packaged
Collector configuration.
# Target Users

## Security Analysts

- Monitor security events
- Investigate incidents
- Analyze evidence


## Security Administrators

- Configure deployment
- Manage security operations
- Maintain system availability


## Enterprise Security Teams

- Improve monitoring visibility
- Support incident response processes
- Maintain security governance

---

# Deployment Model

AegisGuard supports:

- Single-server deployment
- Enterprise server deployment
- Distributed deployment architecture

Deployment requirements depend on event volume, retention requirements, and infrastructure capacity.
