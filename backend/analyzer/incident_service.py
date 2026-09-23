"""Domain service for the AegisGuard unified incident platform."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Iterable, Optional

from backend.analyzer.detection.contracts import IncidentCandidate
from backend.platform.contracts import IncidentLifecycleStatus
from backend.storage.audit_integrity import DEFAULT_AUDIT_RETENTION_DAYS
from backend.storage.audit_log import record_audit_event
from backend.storage.incidents import (
    assign_incident_user,
    get_assignment_user,
    get_incident_by_candidate_id,
    get_incident_detail,
    get_incident_row,
    insert_incident_candidate,
    insert_incident_evidence_reference,
    insert_incident_note,
    list_incident_summaries,
    update_incident_lifecycle,
)


_INCIDENT_ID_VERSION = "incident-platform-v1"
_EVIDENCE_TYPE_PATTERN = re.compile(r"^[A-Z0-9_.:-]+$")

_ALLOWED_TRANSITIONS = {
    IncidentLifecycleStatus.OPEN.value: {
        IncidentLifecycleStatus.INVESTIGATING.value,
    },
    IncidentLifecycleStatus.INVESTIGATING.value: {
        IncidentLifecycleStatus.CONFIRMED.value,
        IncidentLifecycleStatus.FALSE_POSITIVE.value,
    },
    IncidentLifecycleStatus.CONFIRMED.value: {
        IncidentLifecycleStatus.CONTAINMENT.value,
    },
    IncidentLifecycleStatus.FALSE_POSITIVE.value: {
        IncidentLifecycleStatus.CLOSED.value,
    },
    IncidentLifecycleStatus.CONTAINMENT.value: {
        IncidentLifecycleStatus.RESOLVED.value,
    },
    IncidentLifecycleStatus.RESOLVED.value: {
        IncidentLifecycleStatus.CLOSED.value,
    },
    IncidentLifecycleStatus.CLOSED.value: set(),
}


class IncidentPlatformError(ValueError):
    """Base S6 incident-platform error."""


class IncidentValidationError(IncidentPlatformError):
    pass


class IncidentNotFoundError(IncidentPlatformError):
    pass


class IncidentConflictError(IncidentPlatformError):
    pass


class IncidentTransitionError(IncidentPlatformError):
    pass


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _bounded_text(
    value,
    *,
    field_name: str,
    max_length: int,
    required: bool = True,
) -> Optional[str]:
    if value is None:
        if required:
            raise IncidentValidationError(
                f"{field_name} is required"
            )
        return None

    text = str(value).strip()
    if not text:
        if required:
            raise IncidentValidationError(
                f"{field_name} is required"
            )
        return None
    if len(text) > max_length:
        raise IncidentValidationError(
            f"{field_name} must be at most {max_length} characters"
        )
    return text


def deterministic_incident_id(candidate_id: str) -> str:
    candidate_value = _bounded_text(
        candidate_id,
        field_name="candidate_id",
        max_length=256,
    )
    material = (
        f"{_INCIDENT_ID_VERSION}|{candidate_value}"
    ).encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:24].upper()
    return f"INC-{digest}"


def candidate_fingerprint(candidate: IncidentCandidate) -> str:
    if not isinstance(candidate, IncidentCandidate):
        raise TypeError(
            "candidate must be an IncidentCandidate"
        )
    encoded = json.dumps(
        candidate.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _first(values: Iterable[str]) -> Optional[str]:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return None


def persist_incident_candidate(
    conn,
    candidate: IncidentCandidate,
    *,
    audit_retention_days: int = DEFAULT_AUDIT_RETENTION_DAYS,
):
    """Deterministically convert one intelligence IncidentCandidate.

    Identical retries return the existing incident. Reuse of a candidate_id
    with different candidate content fails closed.
    """

    if not isinstance(candidate, IncidentCandidate):
        raise TypeError(
            "candidate must be an IncidentCandidate"
        )

    fingerprint = candidate_fingerprint(candidate)
    existing = get_incident_by_candidate_id(
        conn,
        candidate.candidate_id,
    )
    if existing is not None:
        existing_fingerprint = str(
            existing["candidate_fingerprint"] or ""
        )
        if existing_fingerprint != fingerprint:
            raise IncidentConflictError(
                "candidate_id already exists with different content"
            )
        return (
            get_incident_detail(
                conn,
                str(existing["incident_id"]),
            ),
            False,
        )

    metadata = (
        dict(candidate.metadata)
        if isinstance(candidate.metadata, dict)
        else dict(candidate.metadata or {})
    )
    story_version = str(
        metadata.get("story_version") or ""
    ).strip() or None
    attack_story_id = (
        candidate.candidate_id
        if story_version
        else None
    )

    related_entities = {
        str(key): tuple(
            str(value).strip()
            for value in values
            if str(value or "").strip()
        )
        for key, values in candidate.related_entities.items()
    }

    compatibility = {
        "hostname": _first(
            related_entities.get("hostnames", ())
        ),
        "source_ip": _first(
            related_entities.get("source_ips", ())
        ),
        "user": _first(
            related_entities.get("users", ())
        ),
        "process": _first(
            related_entities.get("processes", ())
        ),
    }

    incident_id = deterministic_incident_id(
        candidate.candidate_id
    )
    opened_at = _utc_now()
    incident, created = insert_incident_candidate(
        conn,
        incident_id=incident_id,
        candidate_id=candidate.candidate_id,
        candidate_fingerprint=fingerprint,
        title=candidate.name,
        severity=candidate.severity.value,
        confidence=float(candidate.confidence),
        reason=candidate.reason,
        observed_at=candidate.timestamp,
        opened_at=opened_at,
        attack_story_id=attack_story_id,
        attack_story_version=story_version,
        finding_ids=candidate.finding_ids,
        event_ids=candidate.event_ids,
        mitre_mappings=(
            mapping.to_dict()
            for mapping in candidate.mitre
        ),
        related_entities=related_entities,
        compatibility=compatibility,
        history_id="hist-" + uuid.uuid4().hex,
    )

    if not created:
        stored_fingerprint = str(
            (
                get_incident_by_candidate_id(
                    conn,
                    candidate.candidate_id,
                )
            )["candidate_fingerprint"]
            or ""
        )
        if stored_fingerprint != fingerprint:
            raise IncidentConflictError(
                "candidate_id already exists with different content"
            )
        return incident, False

    record_audit_event(
        conn,
        actor_type="SYSTEM",
        action="INCIDENT.CREATE",
        outcome="SUCCESS",
        target_type="INCIDENT",
        target_id=incident_id,
        details={
            "candidate_id": candidate.candidate_id,
            "finding_count": len(candidate.finding_ids),
            "event_count": len(candidate.event_ids),
            "attack_story_linked": bool(attack_story_id),
        },
        retention_days=audit_retention_days,
    )
    return incident, True


def persist_incident_candidates(
    conn,
    candidates: Iterable[IncidentCandidate],
    *,
    audit_retention_days: int = DEFAULT_AUDIT_RETENTION_DAYS,
):
    return tuple(
        persist_incident_candidate(
            conn,
            candidate,
            audit_retention_days=audit_retention_days,
        )
        for candidate in candidates
    )


def list_incidents(conn, *, limit: int = 500):
    return list_incident_summaries(
        conn,
        limit=limit,
    )


def get_incident(conn, incident_id: str):
    incident_value = _bounded_text(
        incident_id,
        field_name="incident_id",
        max_length=256,
    )
    incident = get_incident_detail(
        conn,
        incident_value,
    )
    if incident is None:
        raise IncidentNotFoundError(
            "incident not found"
        )
    return incident


def _current_status(conn, incident_id: str) -> str:
    row = get_incident_row(conn, incident_id)
    if row is None:
        raise IncidentNotFoundError(
            "incident not found"
        )
    return str(
        row["lifecycle_status"] or "OPEN"
    ).upper()


def transition_incident(
    conn,
    *,
    incident_id: str,
    to_status: str,
    actor_user_id: str,
    resolution_summary: Optional[str] = None,
):
    incident_value = _bounded_text(
        incident_id,
        field_name="incident_id",
        max_length=256,
    )
    actor_value = _bounded_text(
        actor_user_id,
        field_name="actor_user_id",
        max_length=256,
    )
    target_status = _bounded_text(
        to_status,
        field_name="to_status",
        max_length=64,
    ).upper()

    if target_status not in {
        status.value
        for status in IncidentLifecycleStatus
    }:
        raise IncidentValidationError(
            "invalid lifecycle status"
        )

    current = _current_status(
        conn,
        incident_value,
    )
    if target_status not in _ALLOWED_TRANSITIONS[current]:
        raise IncidentTransitionError(
            f"invalid transition {current} -> {target_status}"
        )

    summary = None
    disposition = None
    resolved_at = None
    now = _utc_now()

    if target_status in {
        IncidentLifecycleStatus.FALSE_POSITIVE.value,
        IncidentLifecycleStatus.RESOLVED.value,
    }:
        summary = _bounded_text(
            resolution_summary,
            field_name="resolution_summary",
            max_length=4000,
        )
        resolved_at = now
        disposition = (
            "FALSE_POSITIVE"
            if target_status
            == IncidentLifecycleStatus.FALSE_POSITIVE.value
            else "RESOLVED"
        )
    elif resolution_summary is not None:
        summary = _bounded_text(
            resolution_summary,
            field_name="resolution_summary",
            max_length=4000,
            required=False,
        )

    closed_at = (
        now
        if target_status
        == IncidentLifecycleStatus.CLOSED.value
        else None
    )

    updated = update_incident_lifecycle(
        conn,
        incident_id=incident_value,
        from_status=current,
        to_status=target_status,
        actor_user_id=actor_value,
        history_id="hist-" + uuid.uuid4().hex,
        created_at=now,
        reason=None,
        resolution_summary=summary,
        disposition=disposition,
        resolved_at=resolved_at,
        closed_at=closed_at,
        administrative_override=False,
    )
    if not updated:
        raise IncidentConflictError(
            "incident lifecycle changed concurrently"
        )
    return get_incident(
        conn,
        incident_value,
    )


def override_incident_status(
    conn,
    *,
    incident_id: str,
    to_status: str,
    actor_user_id: str,
    reason: str,
):
    incident_value = _bounded_text(
        incident_id,
        field_name="incident_id",
        max_length=256,
    )
    actor_value = _bounded_text(
        actor_user_id,
        field_name="actor_user_id",
        max_length=256,
    )
    target_status = _bounded_text(
        to_status,
        field_name="to_status",
        max_length=64,
    ).upper()
    reason_value = _bounded_text(
        reason,
        field_name="reason",
        max_length=1000,
    )

    valid_statuses = {
        status.value
        for status in IncidentLifecycleStatus
    }
    if target_status not in valid_statuses:
        raise IncidentValidationError(
            "invalid lifecycle status"
        )

    current = _current_status(
        conn,
        incident_value,
    )
    if target_status == current:
        raise IncidentTransitionError(
            "administrative override must change status"
        )

    now = _utc_now()
    resolved_at = (
        now
        if target_status in {
            IncidentLifecycleStatus.FALSE_POSITIVE.value,
            IncidentLifecycleStatus.RESOLVED.value,
        }
        else None
    )
    closed_at = (
        now
        if target_status
        == IncidentLifecycleStatus.CLOSED.value
        else None
    )
    disposition = (
        "FALSE_POSITIVE"
        if target_status
        == IncidentLifecycleStatus.FALSE_POSITIVE.value
        else (
            "RESOLVED"
            if target_status
            == IncidentLifecycleStatus.RESOLVED.value
            else None
        )
    )

    updated = update_incident_lifecycle(
        conn,
        incident_id=incident_value,
        from_status=current,
        to_status=target_status,
        actor_user_id=actor_value,
        history_id="hist-" + uuid.uuid4().hex,
        created_at=now,
        reason=reason_value,
        resolution_summary=None,
        disposition=disposition,
        resolved_at=resolved_at,
        closed_at=closed_at,
        administrative_override=True,
    )
    if not updated:
        raise IncidentConflictError(
            "incident lifecycle changed concurrently"
        )
    return get_incident(
        conn,
        incident_value,
    )


def assign_incident(
    conn,
    *,
    incident_id: str,
    assigned_user_id: Optional[str],
    actor_user_id: str,
):
    incident_value = _bounded_text(
        incident_id,
        field_name="incident_id",
        max_length=256,
    )
    actor_value = _bounded_text(
        actor_user_id,
        field_name="actor_user_id",
        max_length=256,
    )

    if get_incident_row(conn, incident_value) is None:
        raise IncidentNotFoundError(
            "incident not found"
        )

    target_user = None
    if assigned_user_id is not None:
        target_user = _bounded_text(
            assigned_user_id,
            field_name="assigned_user_id",
            max_length=256,
        )
        row = get_assignment_user(
            conn,
            target_user,
        )
        if (
            row is None
            or not bool(row["active"])
            or str(row["role"]).upper()
            not in {"ANALYST", "ADMINISTRATOR"}
        ):
            raise IncidentValidationError(
                "assigned user must be an active analyst or administrator"
            )

    updated = assign_incident_user(
        conn,
        incident_id=incident_value,
        assigned_user_id=target_user,
        actor_user_id=actor_value,
        history_id="hist-" + uuid.uuid4().hex,
        created_at=_utc_now(),
    )
    if not updated:
        raise IncidentNotFoundError(
            "incident not found"
        )
    return get_incident(
        conn,
        incident_value,
    )


def add_incident_note(
    conn,
    *,
    incident_id: str,
    actor_user_id: str,
    note: str,
):
    incident_value = _bounded_text(
        incident_id,
        field_name="incident_id",
        max_length=256,
    )
    actor_value = _bounded_text(
        actor_user_id,
        field_name="actor_user_id",
        max_length=256,
    )
    note_value = _bounded_text(
        note,
        field_name="note",
        max_length=4000,
    )
    note_id = "note-" + uuid.uuid4().hex
    created_at = _utc_now()

    inserted = insert_incident_note(
        conn,
        note_id=note_id,
        incident_id=incident_value,
        author_user_id=actor_value,
        body=note_value,
        created_at=created_at,
    )
    if not inserted:
        raise IncidentNotFoundError(
            "incident not found"
        )
    return {
        "note_id": note_id,
        "incident_id": incident_value,
        "author_user_id": actor_value,
        "body": note_value,
        "created_at": created_at,
    }


def add_incident_evidence(
    conn,
    *,
    incident_id: str,
    actor_user_id: str,
    reference_type: str,
    reference_id: str,
    description: Optional[str] = None,
):
    incident_value = _bounded_text(
        incident_id,
        field_name="incident_id",
        max_length=256,
    )
    actor_value = _bounded_text(
        actor_user_id,
        field_name="actor_user_id",
        max_length=256,
    )
    type_value = _bounded_text(
        reference_type,
        field_name="reference_type",
        max_length=64,
    ).upper()
    if not _EVIDENCE_TYPE_PATTERN.fullmatch(type_value):
        raise IncidentValidationError(
            "invalid evidence reference_type"
        )
    reference_value = _bounded_text(
        reference_id,
        field_name="reference_id",
        max_length=512,
    )
    description_value = _bounded_text(
        description,
        field_name="description",
        max_length=1000,
        required=False,
    )

    evidence_id = "evidence-" + uuid.uuid4().hex
    created_at = _utc_now()
    exists, created = insert_incident_evidence_reference(
        conn,
        evidence_id=evidence_id,
        incident_id=incident_value,
        reference_type=type_value,
        reference_id=reference_value,
        description=description_value,
        added_by_user_id=actor_value,
        created_at=created_at,
    )
    if not exists:
        raise IncidentNotFoundError(
            "incident not found"
        )

    if not created:
        incident = get_incident(
            conn,
            incident_value,
        )
        for evidence in incident["evidence_references"]:
            if (
                evidence["reference_type"] == type_value
                and evidence["reference_id"] == reference_value
            ):
                evidence["duplicate"] = True
                return evidence

    return {
        "evidence_id": evidence_id,
        "incident_id": incident_value,
        "reference_type": type_value,
        "reference_id": reference_value,
        "description": description_value,
        "added_by_user_id": actor_value,
        "created_at": created_at,
        "duplicate": False,
    }
