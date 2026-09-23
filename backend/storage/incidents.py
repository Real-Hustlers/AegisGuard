"""Persistent unified incident storage for AegisGuard Enterprise."""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable, Mapping, Optional


def _json_load(value, default):
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def _row_to_mapping(row) -> dict[str, Any]:
    if row is None:
        return {}
    if isinstance(row, sqlite3.Row):
        return dict(row)
    try:
        return dict(row)
    except (TypeError, ValueError):
        raise TypeError("incident storage requires sqlite3.Row-compatible rows")


def _summary_from_row(row) -> dict[str, Any]:
    item = _row_to_mapping(row)
    report = _json_load(item.get("incident_report"), None)
    legacy_mitre = _json_load(item.get("mitre"), None)
    return {
        "incident_id": item.get("incident_id"),
        "candidate_id": item.get("candidate_id"),
        "title": (
            item.get("title")
            or item.get("threat_type")
            or item.get("incident_id")
        ),
        "threat_type": item.get("threat_type"),
        "description": item.get("description"),
        "severity": item.get("severity"),
        "confidence": item.get("confidence"),
        "lifecycle_status": (
            item.get("lifecycle_status") or "OPEN"
        ),
        "assigned_user_id": item.get("assigned_user_id"),
        "opened_at": item.get("opened_at") or item.get("timestamp"),
        "updated_at": item.get("updated_at"),
        "resolved_at": item.get("resolved_at"),
        "closed_at": item.get("closed_at"),
        "resolution_summary": item.get("resolution_summary"),
        "disposition": item.get("disposition"),
        "attack_story_id": item.get("attack_story_id"),
        "attack_story_version": item.get("attack_story_version"),
        "candidate_observed_at": item.get("timestamp"),
        # Preserve the legacy status for old dashboard consumers.
        "status": item.get("status"),
        "legacy_status": item.get("status"),
        "hostname": item.get("hostname"),
        "os": item.get("os"),
        "source_ip": item.get("source_ip"),
        "user": item.get("user"),
        "process": item.get("process"),
        "file_path": item.get("file_path"),
        "alert_status": item.get("alert_status"),
        "incident_report": report,
        "ml_prediction": (
            report.get("ml_prediction")
            if isinstance(report, dict)
            else None
        ),
        "ml_confidence": (
            report.get("ml_confidence")
            if isinstance(report, dict)
            else None
        ),
        "mitre": legacy_mitre,
    }


def list_incident_summaries(conn, *, limit: int = 500) -> list[dict[str, Any]]:
    limit_value = int(limit)
    if limit_value <= 0 or limit_value > 500:
        raise ValueError("incident list limit must be between 1 and 500")

    rows = conn.execute(
        """
        SELECT *
        FROM incidents
        ORDER BY
            COALESCE(opened_at, timestamp, updated_at) DESC,
            incident_id DESC
        LIMIT ?
        """,
        (limit_value,),
    ).fetchall()
    return [_summary_from_row(row) for row in rows]


def get_incident_by_candidate_id(conn, candidate_id: str):
    return conn.execute(
        """
        SELECT *
        FROM incidents
        WHERE candidate_id = ?
        """,
        (candidate_id,),
    ).fetchone()


def get_incident_row(conn, incident_id: str):
    return conn.execute(
        """
        SELECT *
        FROM incidents
        WHERE incident_id = ?
        """,
        (incident_id,),
    ).fetchone()


def get_assignment_user(conn, user_id: str):
    return conn.execute(
        """
        SELECT user_id, username, role, active
        FROM users
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()


def _load_reference_values(
    conn,
    table: str,
    column: str,
    incident_id: str,
):
    return [
        row[0]
        for row in conn.execute(
            f"""
            SELECT {column}
            FROM {table}
            WHERE incident_id = ?
            ORDER BY {column} ASC
            """,
            (incident_id,),
        ).fetchall()
    ]


def get_incident_detail(conn, incident_id: str) -> Optional[dict[str, Any]]:
    row = get_incident_row(conn, incident_id)
    if row is None:
        return None

    detail = _summary_from_row(row)

    detail["finding_ids"] = _load_reference_values(
        conn,
        "incident_finding_refs",
        "finding_id",
        incident_id,
    )
    detail["event_ids"] = _load_reference_values(
        conn,
        "incident_event_refs",
        "event_id",
        incident_id,
    )

    detail["mitre_mappings"] = [
        {
            "technique_id": row[0],
            "technique": row[1],
            "tactic": row[2],
        }
        for row in conn.execute(
            """
            SELECT technique_id, technique, tactic
            FROM incident_mitre_mappings
            WHERE incident_id = ?
            ORDER BY technique_id, tactic
            """,
            (incident_id,),
        ).fetchall()
    ]

    entities: dict[str, list[str]] = {}
    for entity_type, entity_value in conn.execute(
        """
        SELECT entity_type, entity_value
        FROM incident_related_entities
        WHERE incident_id = ?
        ORDER BY entity_type, entity_value
        """,
        (incident_id,),
    ).fetchall():
        entities.setdefault(str(entity_type), []).append(
            str(entity_value)
        )
    detail["related_entities"] = entities

    detail["notes"] = [
        {
            "note_id": row[0],
            "author_user_id": row[1],
            "body": row[2],
            "created_at": row[3],
        }
        for row in conn.execute(
            """
            SELECT note_id,
                   author_user_id,
                   body,
                   created_at
            FROM incident_notes
            WHERE incident_id = ?
            ORDER BY created_at ASC, note_id ASC
            """,
            (incident_id,),
        ).fetchall()
    ]

    detail["evidence_references"] = [
        {
            "evidence_id": row[0],
            "reference_type": row[1],
            "reference_id": row[2],
            "description": row[3],
            "added_by_user_id": row[4],
            "created_at": row[5],
        }
        for row in conn.execute(
            """
            SELECT evidence_id,
                   reference_type,
                   reference_id,
                   description,
                   added_by_user_id,
                   created_at
            FROM incident_evidence_refs
            WHERE incident_id = ?
            ORDER BY created_at ASC, evidence_id ASC
            """,
            (incident_id,),
        ).fetchall()
    ]

    detail["lifecycle_history"] = [
        {
            "history_id": row[0],
            "from_status": row[1],
            "to_status": row[2],
            "actor_user_id": row[3],
            "action": row[4],
            "reason": row[5],
            "administrative_override": bool(row[6]),
            "created_at": row[7],
        }
        for row in conn.execute(
            """
            SELECT history_id,
                   from_status,
                   to_status,
                   actor_user_id,
                   action,
                   reason,
                   administrative_override,
                   created_at
            FROM incident_lifecycle_history
            WHERE incident_id = ?
            ORDER BY created_at ASC, history_id ASC
            """,
            (incident_id,),
        ).fetchall()
    ]

    return detail


def insert_incident_candidate(
    conn,
    *,
    incident_id: str,
    candidate_id: str,
    candidate_fingerprint: str,
    title: str,
    severity: str,
    confidence: float,
    reason: str,
    observed_at: str,
    opened_at: str,
    attack_story_id: Optional[str],
    attack_story_version: Optional[str],
    finding_ids: Iterable[str],
    event_ids: Iterable[str],
    mitre_mappings: Iterable[Mapping[str, str]],
    related_entities: Mapping[str, Iterable[str]],
    compatibility: Mapping[str, Optional[str]],
    history_id: str,
):
    """Insert one candidate-derived incident atomically.

    Returns (incident_detail, created). The unique candidate_id index provides
    retry idempotency under concurrent callers.
    """

    conn.execute("BEGIN IMMEDIATE")
    try:
        existing = get_incident_by_candidate_id(
            conn,
            candidate_id,
        )
        if existing is not None:
            conn.commit()
            return (
                get_incident_detail(
                    conn,
                    str(existing["incident_id"]),
                ),
                False,
            )

        conn.execute(
            """
            INSERT INTO incidents(
                incident_id,
                candidate_id,
                candidate_fingerprint,
                title,
                threat_type,
                description,
                severity,
                confidence,
                timestamp,
                status,
                lifecycle_status,
                opened_at,
                updated_at,
                attack_story_id,
                attack_story_version,
                hostname,
                source_ip,
                user,
                process
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                candidate_id,
                candidate_fingerprint,
                title,
                title,
                reason,
                severity,
                float(confidence),
                observed_at,
                "OPEN",
                "OPEN",
                opened_at,
                opened_at,
                attack_story_id,
                attack_story_version,
                compatibility.get("hostname"),
                compatibility.get("source_ip"),
                compatibility.get("user"),
                compatibility.get("process"),
            ),
        )

        for finding_id in finding_ids:
            conn.execute(
                """
                INSERT OR IGNORE INTO incident_finding_refs(
                    incident_id,
                    finding_id
                ) VALUES (?, ?)
                """,
                (incident_id, finding_id),
            )

        for event_id in event_ids:
            conn.execute(
                """
                INSERT OR IGNORE INTO incident_event_refs(
                    incident_id,
                    event_id
                ) VALUES (?, ?)
                """,
                (incident_id, event_id),
            )

        for mapping in mitre_mappings:
            conn.execute(
                """
                INSERT OR IGNORE INTO incident_mitre_mappings(
                    incident_id,
                    technique_id,
                    technique,
                    tactic
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    incident_id,
                    mapping["technique_id"],
                    mapping["technique"],
                    mapping["tactic"],
                ),
            )

        for entity_type, values in related_entities.items():
            for value in values:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO incident_related_entities(
                        incident_id,
                        entity_type,
                        entity_value
                    ) VALUES (?, ?, ?)
                    """,
                    (incident_id, entity_type, value),
                )

        conn.execute(
            """
            INSERT INTO incident_lifecycle_history(
                history_id,
                incident_id,
                from_status,
                to_status,
                actor_user_id,
                action,
                reason,
                administrative_override,
                created_at
            ) VALUES (?, ?, NULL, 'OPEN', NULL, 'CREATED', ?, 0, ?)
            """,
            (
                history_id,
                incident_id,
                "Created from IncidentCandidate",
                opened_at,
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return get_incident_detail(conn, incident_id), True


def update_incident_lifecycle(
    conn,
    *,
    incident_id: str,
    from_status: str,
    to_status: str,
    actor_user_id: str,
    history_id: str,
    created_at: str,
    reason: Optional[str],
    resolution_summary: Optional[str],
    disposition: Optional[str],
    resolved_at: Optional[str],
    closed_at: Optional[str],
    administrative_override: bool,
):
    conn.execute("BEGIN IMMEDIATE")
    try:
        cursor = conn.execute(
            """
            UPDATE incidents
            SET lifecycle_status = ?,
                updated_at = ?,
                resolution_summary = COALESCE(?, resolution_summary),
                disposition = COALESCE(?, disposition),
                resolved_at = COALESCE(?, resolved_at),
                closed_at = COALESCE(?, closed_at)
            WHERE incident_id = ?
              AND lifecycle_status = ?
            """,
            (
                to_status,
                created_at,
                resolution_summary,
                disposition,
                resolved_at,
                closed_at,
                incident_id,
                from_status,
            ),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return False

        conn.execute(
            """
            INSERT INTO incident_lifecycle_history(
                history_id,
                incident_id,
                from_status,
                to_status,
                actor_user_id,
                action,
                reason,
                administrative_override,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                history_id,
                incident_id,
                from_status,
                to_status,
                actor_user_id,
                (
                    "ADMIN_OVERRIDE"
                    if administrative_override
                    else "TRANSITION"
                ),
                reason,
                1 if administrative_override else 0,
                created_at,
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return True


def assign_incident_user(
    conn,
    *,
    incident_id: str,
    assigned_user_id: Optional[str],
    actor_user_id: str,
    history_id: str,
    created_at: str,
):
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = get_incident_row(conn, incident_id)
        if row is None:
            conn.rollback()
            return False

        current_status = str(row["lifecycle_status"] or "OPEN")
        conn.execute(
            """
            UPDATE incidents
            SET assigned_user_id = ?,
                updated_at = ?
            WHERE incident_id = ?
            """,
            (
                assigned_user_id,
                created_at,
                incident_id,
            ),
        )
        conn.execute(
            """
            INSERT INTO incident_lifecycle_history(
                history_id,
                incident_id,
                from_status,
                to_status,
                actor_user_id,
                action,
                reason,
                administrative_override,
                created_at
            ) VALUES (?, ?, ?, ?, ?, 'ASSIGNMENT', ?, 1, ?)
            """,
            (
                history_id,
                incident_id,
                current_status,
                current_status,
                actor_user_id,
                (
                    f"assigned_user_id={assigned_user_id}"
                    if assigned_user_id
                    else "incident unassigned"
                ),
                created_at,
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return True


def insert_incident_note(
    conn,
    *,
    note_id: str,
    incident_id: str,
    author_user_id: str,
    body: str,
    created_at: str,
):
    conn.execute("BEGIN IMMEDIATE")
    try:
        if get_incident_row(conn, incident_id) is None:
            conn.rollback()
            return False

        conn.execute(
            """
            INSERT INTO incident_notes(
                note_id,
                incident_id,
                author_user_id,
                body,
                created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                note_id,
                incident_id,
                author_user_id,
                body,
                created_at,
            ),
        )
        conn.execute(
            """
            UPDATE incidents
            SET updated_at = ?
            WHERE incident_id = ?
            """,
            (created_at, incident_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return True


def insert_incident_evidence_reference(
    conn,
    *,
    evidence_id: str,
    incident_id: str,
    reference_type: str,
    reference_id: str,
    description: Optional[str],
    added_by_user_id: str,
    created_at: str,
):
    conn.execute("BEGIN IMMEDIATE")
    try:
        if get_incident_row(conn, incident_id) is None:
            conn.rollback()
            return False, False

        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO incident_evidence_refs(
                evidence_id,
                incident_id,
                reference_type,
                reference_id,
                description,
                added_by_user_id,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                incident_id,
                reference_type,
                reference_id,
                description,
                added_by_user_id,
                created_at,
            ),
        )
        created = cursor.rowcount == 1
        if created:
            conn.execute(
                """
                UPDATE incidents
                SET updated_at = ?
                WHERE incident_id = ?
                """,
                (created_at, incident_id),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return True, created
