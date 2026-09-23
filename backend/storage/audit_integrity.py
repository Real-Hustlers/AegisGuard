"""Tamper-evident integrity and retention primitives for audit events."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Optional


GENESIS_AUDIT_HASH = "0" * 64
DEFAULT_AUDIT_RETENTION_DAYS = 365
MAX_AUDIT_RETENTION_DAYS = 3650


class AuditIntegrityError(ValueError):
    """Raised when audit-chain or retention values are structurally invalid."""


def _parse_timestamp(value: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise AuditIntegrityError("audit timestamp is required")
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_retention_days(value: int) -> int:
    days = int(value)
    if days <= 0:
        raise AuditIntegrityError(
            "audit retention days must be greater than zero"
        )
    if days > MAX_AUDIT_RETENTION_DAYS:
        raise AuditIntegrityError(
            f"audit retention days must be <= {MAX_AUDIT_RETENTION_DAYS}"
        )
    return days


def retention_until_for_timestamp(
    timestamp: str,
    retention_days: int = DEFAULT_AUDIT_RETENTION_DAYS,
) -> str:
    days = validate_retention_days(retention_days)
    return _format_timestamp(
        _parse_timestamp(timestamp) + timedelta(days=days)
    )


def canonical_audit_hash_payload(
    *,
    chain_sequence: int,
    audit_id: str,
    timestamp: str,
    actor_user_id: Optional[str],
    actor_type: str,
    action: str,
    target_type: Optional[str],
    target_id: Optional[str],
    outcome: str,
    peer_ip: Optional[str],
    correlation_id: Optional[str],
    details_json: str,
    retention_until: str,
    previous_hash: str,
) -> bytes:
    payload = {
        "chain_sequence": int(chain_sequence),
        "audit_id": str(audit_id),
        "timestamp": str(timestamp),
        "actor_user_id": actor_user_id,
        "actor_type": str(actor_type),
        "action": str(action),
        "target_type": target_type,
        "target_id": target_id,
        "outcome": str(outcome),
        "peer_ip": peer_ip,
        "correlation_id": correlation_id,
        "details_json": str(details_json),
        "retention_until": str(retention_until),
        "previous_hash": str(previous_hash),
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_audit_event_hash(**fields: Any) -> str:
    return hashlib.sha256(
        canonical_audit_hash_payload(**fields)
    ).hexdigest()


def verify_audit_chain(conn) -> dict[str, Any]:
    """Verify sequence continuity, linkage, and event content hashes."""

    rows = conn.execute(
        """
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
        ORDER BY chain_sequence ASC
        """
    ).fetchall()

    if not rows:
        return {
            "valid": True,
            "event_count": 0,
            "first_sequence": None,
            "last_sequence": None,
            "head_hash": GENESIS_AUDIT_HASH,
            "failure_sequence": None,
            "reason": None,
        }

    expected_previous = GENESIS_AUDIT_HASH
    expected_sequence = 1

    for row in rows:
        sequence = int(row[0])
        if sequence != expected_sequence:
            return {
                "valid": False,
                "event_count": len(rows),
                "first_sequence": int(rows[0][0]),
                "last_sequence": int(rows[-1][0]),
                "head_hash": str(rows[-1][14] or ""),
                "failure_sequence": sequence,
                "reason": "sequence_gap",
            }

        previous_hash = str(row[13] or "")
        if previous_hash != expected_previous:
            return {
                "valid": False,
                "event_count": len(rows),
                "first_sequence": int(rows[0][0]),
                "last_sequence": int(rows[-1][0]),
                "head_hash": str(rows[-1][14] or ""),
                "failure_sequence": sequence,
                "reason": "previous_hash_mismatch",
            }

        expected_hash = compute_audit_event_hash(
            chain_sequence=sequence,
            audit_id=row[1],
            timestamp=row[2],
            actor_user_id=row[3],
            actor_type=row[4],
            action=row[5],
            target_type=row[6],
            target_id=row[7],
            outcome=row[8],
            peer_ip=row[9],
            correlation_id=row[10],
            details_json=row[11],
            retention_until=row[12],
            previous_hash=previous_hash,
        )
        actual_hash = str(row[14] or "")
        if actual_hash != expected_hash:
            return {
                "valid": False,
                "event_count": len(rows),
                "first_sequence": int(rows[0][0]),
                "last_sequence": int(rows[-1][0]),
                "head_hash": str(rows[-1][14] or ""),
                "failure_sequence": sequence,
                "reason": "event_hash_mismatch",
            }

        expected_previous = actual_hash
        expected_sequence += 1

    return {
        "valid": True,
        "event_count": len(rows),
        "first_sequence": int(rows[0][0]),
        "last_sequence": int(rows[-1][0]),
        "head_hash": str(rows[-1][14]),
        "failure_sequence": None,
        "reason": None,
    }
