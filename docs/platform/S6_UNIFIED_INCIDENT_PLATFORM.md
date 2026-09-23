# S6 — Unified Incident Platform

S6 establishes the persistent incident lifecycle owned by the AegisGuard
platform. It consumes Yogendiran-owned `IncidentCandidate` objects but does not
change detection, ML, correlation, MITRE resolution, or attack-story semantics.

## Ownership boundary

Intelligence owns:

```text
DetectionFinding
    ↓
IncidentCandidate
```

S6 owns:

```text
IncidentCandidate
    ↓
Persistent Incident
    ↓
Lifecycle / Assignment / Evidence / Notes
    ↓
Authenticated SOC API
```

Response execution remains outside S6 and belongs to S8 governance.

## Schema v10

S6 extends the existing legacy `incidents` table instead of replacing it.

Added incident columns:

```text
candidate_id
candidate_fingerprint
confidence
attack_story_id
attack_story_version
opened_at
resolution_summary
```

Added normalized tables:

```text
incident_finding_refs
incident_event_refs
incident_mitre_mappings
incident_related_entities
incident_notes
incident_evidence_refs
incident_lifecycle_history
```

Raw event bodies are not copied into S6 incident storage.

## Idempotent candidate conversion

The persistent incident ID is deterministic:

```text
INC-<SHA256(incident-platform-v1 | candidate_id)[:24]>
```

`candidate_id` is protected by a unique index.

A SHA-256 fingerprint of the complete `IncidentCandidate.to_dict()` payload is
stored.

Behavior:

- identical retry → return the existing incident;
- same candidate_id with changed content → fail closed with conflict;
- successful first creation → exactly one `INCIDENT.CREATE` audit event.

## Lifecycle

Normal analyst lifecycle:

```text
OPEN
  ↓
INVESTIGATING
  ├─→ CONFIRMED
  │      ↓
  │  CONTAINMENT
  │      ↓
  │   RESOLVED
  │      ↓
  │    CLOSED
  │
  └─→ FALSE_POSITIVE
          ↓
        CLOSED
```

`FALSE_POSITIVE` and `RESOLVED` require a resolution summary.

Invalid normal transitions fail with conflict.

Administrators have an explicit override endpoint that may move an incident to
another valid lifecycle status only when a reason is supplied. This is a
workflow-state override only; it does not execute response actions.

## RBAC

VIEWER:

- list incidents;
- read incident details.

ANALYST:

- all viewer reads;
- normal lifecycle transition;
- add analyst notes;
- add evidence references.

ADMINISTRATOR:

- all analyst permissions;
- assign/unassign incidents;
- lifecycle override with mandatory reason.

All mutations remain protected by the existing S4 CSRF boundary.

Client-supplied user/role headers are not used.

## Evidence model

S6 stores references, not arbitrary evidence blobs.

Evidence records contain:

```text
reference_type
reference_id
optional description
server-resolved user
timestamp
```

Duplicate `(incident_id, reference_type, reference_id)` submissions are
idempotent.

## Audit

S6 uses the completed S5 chain.

Audit actions include:

```text
INCIDENT.CREATE
INCIDENT.TRANSITION
INCIDENT.ASSIGN
INCIDENT.NOTE_ADD
INCIDENT.EVIDENCE_ADD
INCIDENT.OVERRIDE
```

Note text and arbitrary evidence content are not copied into audit details.

The S5 SHA-256 chain and retention behavior are preserved.

## Legacy compatibility

The existing `incidents` table remains the canonical table so legacy SOAR
lookups and dashboard code continue to resolve incident IDs.

Legacy columns such as `status`, `threat_type`, `hostname`, and `source_ip`
remain present.

The new lifecycle is authoritative in `lifecycle_status`; legacy `status`
remains available separately for compatibility.

## Response boundary

S6 does not add shell execution, firewall execution, or generic playbook
execution.

Existing safe response behavior remains unchanged:

```text
OBSERVE
→ RECOMMEND
→ SIMULATE
→ APPROVAL
→ CONTROLLED EXECUTION
```

S8 owns response governance.
