# AegisGuard Enterprise S1 Platform Contracts

This document records the first productization contract established from the
verified pre-Codex baseline.

## Ownership boundary

Saran owns persistence, identity, authentication, audit, incident lifecycle,
response governance, collector security, and system operations.

Yogendiran owns detection rules, ML, model evaluation, MITRE mapping,
correlation, attack timelines, detection visualization, and the intelligence
frontend.

The shared contracts in backend/platform/contracts.py are deliberately neutral.
They carry data between those areas without embedding detection or UI behavior.

## Persistence strategy

The existing pre-product SQLite tables are preserved. Versioned migrations are
additive and recorded in platform_schema_migrations.

Schema version 1 adds users, sessions, collectors, assets, events, detections,
incident_events, audit_events, and model_metadata. Existing incidents and
response_actions are extended with enterprise lifecycle/governance fields.

The legacy security_logs table remains intact so current ingestion continues to
work while later phases introduce durable canonical-event writes.

## Safety properties

- No legacy table is dropped or renamed.
- Existing incident status values are not rewritten.
- Existing response-action status values are not rewritten.
- Migration execution is idempotent.
- Migration application is guarded by a SQLite savepoint.
- No ML, detection, correlation, or frontend implementation is changed in S1.
