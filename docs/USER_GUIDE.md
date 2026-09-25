# AegisGuard Enterprise User Guide

## Release

Version: v0.1.0 Release Candidate

## Sign in

Use an AegisGuard application account provisioned by an administrator.

The product uses authenticated sessions and role-based access.

## SOC dashboard

The dashboard provides operational security visibility from product APIs.

Depending on available data, views can include:

- security events;
- alerts;
- Collector health;
- incidents;
- intelligence;
- response-governance state.

Empty views are valid when no matching data exists.

## Events

Event views display ingested security activity.

The installed Windows Collector can send supported Windows Security events to
the Analyzer through the authenticated mTLS Collector path.

## Collector visibility

Important states include:

- enrollment status;
- liveness;
- transport status;
- mTLS verification;
- queue status.

## Intelligence

The Intelligence view can expose:

- rule findings;
- governed ML findings;
- correlation findings;
- MITRE coverage;
- attack-story context.

If none are present, the UI should show an explicit empty state.

If no promoted governed ML model is installed, the runtime can show
UNAVAILABLE.

## Incidents

Incidents appear when the incident pipeline produces persisted incident data.

An empty incident workspace does not imply that event ingestion has failed.

## MITRE ATT&CK

MITRE mappings are shown when supported findings contain mapped technique
context.

The product does not fabricate MITRE mappings when no qualifying finding is
present.

## Response governance

SIMULATED does not mean a live response was executed.

## Roles

- VIEWER: read-only visibility;
- ANALYST: investigation-oriented access;
- ADMINISTRATOR: privileged administrative operations where authorized.

## Operational states

The UI explicitly represents loading, empty, stale, degraded, unavailable, and
error conditions rather than presenting them as successful telemetry.

## Security guidance

Do not share:

- account passwords;
- session tokens;
- CSRF tokens;
- Collector credentials;
- enrollment/recovery tokens;
- private-key material.
