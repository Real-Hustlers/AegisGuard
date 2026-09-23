"""Read-only audit-log query primitives."""

from __future__ import annotations

import json
from typing import Optional

from backend.storage.audit_log import (
    AUDIT_ACTOR_TYPES,
    AUDIT_OUTCOMES,
)


DEFAULT_AUDIT_QUERY_LIMIT = 100
MAX_AUDIT_QUERY_LIMIT = 500


class AuditQueryError(ValueError):
    """Raised for invalid audit query filters."""


def _optional_filter(value: Optional[str], *, upper=False):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text.upper() if upper else text


def query_audit_events(
    conn,
    *,
    limit=DEFAULT_AUDIT_QUERY_LIMIT,
    action=None,
    outcome=None,
    actor_type=None,
    correlation_id=None,
    target_id=None,
):
    limit_value = int(limit)
    if limit_value <= 0 or limit_value > MAX_AUDIT_QUERY_LIMIT:
        raise AuditQueryError(
            f"limit must be between 1 and {MAX_AUDIT_QUERY_LIMIT}"
        )

    action_value = _optional_filter(action, upper=True)
    outcome_value = _optional_filter(outcome, upper=True)
    actor_type_value = _optional_filter(actor_type, upper=True)
    correlation_value = _optional_filter(correlation_id)
    target_value = _optional_filter(target_id)

    if outcome_value is not None and outcome_value not in AUDIT_OUTCOMES:
        raise AuditQueryError(
            "outcome must be SUCCESS, FAILURE, or DENIED"
        )
    if (
        actor_type_value is not None
        and actor_type_value not in AUDIT_ACTOR_TYPES
    ):
        raise AuditQueryError(
            "actor_type must be USER, SYSTEM, or COLLECTOR"
        )

    clauses = []
    params = []
    for column, value in (
        ("action", action_value),
        ("outcome", outcome_value),
        ("actor_type", actor_type_value),
        ("correlation_id", correlation_value),
        ("target_id", target_value),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)

    where_sql = (
        " WHERE " + " AND ".join(clauses)
        if clauses
        else ""
    )

    rows = conn.execute(
        f"""
        SELECT chain_sequence,
               audit_id,
               timestamp,
               actor_user_id,
               actor_type,
               action,
               target_type,
               target_id,
               outcome,
               peer_ip,
               correlation_id,
               details_json,
               retention_until,
               previous_hash,
               event_hash
        FROM audit_events
        {where_sql}
        ORDER BY chain_sequence DESC
        LIMIT ?
        """,
        (*params, limit_value),
    ).fetchall()

    events = []
    for row in rows:
        try:
            details = json.loads(row[11] or "{}")
        except (TypeError, json.JSONDecodeError):
            details = {}

        events.append({
            "chain_sequence": int(row[0]),
            "audit_id": str(row[1]),
            "timestamp": str(row[2]),
            "actor_user_id": row[3],
            "actor_type": str(row[4]),
            "action": str(row[5]),
            "target_type": row[6],
            "target_id": row[7],
            "outcome": str(row[8]),
            "peer_ip": row[9],
            "correlation_id": row[10],
            "details": details,
            "retention_until": row[12],
            "previous_hash": row[13],
            "event_hash": row[14],
        })

    return events
