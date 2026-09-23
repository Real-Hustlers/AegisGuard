"""Append-only audit-event persistence for AegisGuard Enterprise."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from backend.platform.contracts import AuditEvent


AUDIT_ACTOR_TYPES = frozenset({
    "USER",
    "SYSTEM",
    "COLLECTOR",
})

AUDIT_OUTCOMES = frozenset({
    "SUCCESS",
    "FAILURE",
    "DENIED",
})

MAX_DETAILS_JSON_BYTES = 16 * 1024
MAX_DETAIL_STRING_LENGTH = 2048

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "credential",
    "authorization",
    "cookie",
    "csrf",
    "private_key",
    "session_token",
    "access_token",
    "refresh_token",
    "api_key",
)

_ACTION_PATTERN = re.compile(r"^[A-Z0-9_.:-]+$")


class AuditValidationError(ValueError):
    """Raised when an audit event violates the stable audit contract."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _normalize_optional_text(
    value: Optional[str],
    *,
    field_name: str,
    max_length: int = 256,
) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > max_length:
        raise AuditValidationError(
            f"{field_name} must be at most {max_length} characters"
        )
    return text


def _is_sensitive_key(key: Any) -> bool:
    normalized = str(key or "").strip().lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _sanitize_scalar(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value

    text = str(value)
    lowered = text.lower()

    if (
        "-----begin private key-----" in lowered
        or "-----begin rsa private key-----" in lowered
        or lowered.startswith("bearer ")
        or lowered.startswith("basic ")
    ):
        return "[REDACTED]"

    if len(text) > MAX_DETAIL_STRING_LENGTH:
        return text[:MAX_DETAIL_STRING_LENGTH] + "...[TRUNCATED]"
    return text


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        sanitized = {}
        for key, child in value.items():
            key_text = str(key)
            if _is_sensitive_key(key_text):
                sanitized[key_text] = "[REDACTED]"
            else:
                sanitized[key_text] = _sanitize_value(child)
        return sanitized

    if isinstance(value, (list, tuple)):
        return [_sanitize_value(item) for item in value]

    return _sanitize_scalar(value)


def sanitize_audit_details(details: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    """Return JSON-safe audit details with secret-bearing fields removed."""

    if details is None:
        return {}
    if not isinstance(details, Mapping):
        raise AuditValidationError("audit details must be a mapping")

    sanitized = _sanitize_value(details)
    encoded = json.dumps(
        sanitized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    if len(encoded.encode("utf-8")) > MAX_DETAILS_JSON_BYTES:
        raise AuditValidationError(
            f"audit details exceed {MAX_DETAILS_JSON_BYTES} bytes"
        )
    return sanitized


def _normalize_action(action: str) -> str:
    value = str(action or "").strip().upper()
    if not value:
        raise AuditValidationError("action is required")
    if len(value) > 128:
        raise AuditValidationError("action must be at most 128 characters")
    if not _ACTION_PATTERN.fullmatch(value):
        raise AuditValidationError(
            "action may contain only A-Z, 0-9, _, ., :, and -"
        )
    return value


def _normalize_actor_type(actor_type: str) -> str:
    value = str(actor_type or "").strip().upper()
    if value not in AUDIT_ACTOR_TYPES:
        raise AuditValidationError(
            "actor_type must be USER, SYSTEM, or COLLECTOR"
        )
    return value


def _normalize_outcome(outcome: str) -> str:
    value = str(outcome or "").strip().upper()
    if value not in AUDIT_OUTCOMES:
        raise AuditValidationError(
            "outcome must be SUCCESS, FAILURE, or DENIED"
        )
    return value


def record_audit_event(
    conn,
    *,
    actor_type: str,
    action: str,
    outcome: str,
    actor_user_id: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    peer_ip: Optional[str] = None,
    correlation_id: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
    now: Optional[datetime] = None,
) -> AuditEvent:
    """Append one server-generated audit event and return its stable contract.

    Callers cannot supply an audit ID. The writer owns event identity and
    timestamp generation so request payloads cannot forge those fields.
    """

    actor = _normalize_actor_type(actor_type)
    action_value = _normalize_action(action)
    outcome_value = _normalize_outcome(outcome)
    user_id = _normalize_optional_text(
        actor_user_id,
        field_name="actor_user_id",
        max_length=256,
    )

    if actor == "USER" and user_id is None:
        raise AuditValidationError(
            "USER audit events require actor_user_id"
        )
    if actor != "USER" and user_id is not None:
        raise AuditValidationError(
            "actor_user_id is allowed only for USER audit events"
        )

    target_type_value = _normalize_optional_text(
        target_type,
        field_name="target_type",
        max_length=128,
    )
    if target_type_value is not None:
        target_type_value = target_type_value.upper()

    target_id_value = _normalize_optional_text(
        target_id,
        field_name="target_id",
        max_length=512,
    )
    peer_ip_value = _normalize_optional_text(
        peer_ip,
        field_name="peer_ip",
        max_length=128,
    )
    correlation_value = _normalize_optional_text(
        correlation_id,
        field_name="correlation_id",
        max_length=128,
    )
    sanitized_details = sanitize_audit_details(details)

    timestamp_value = _format_timestamp(
        _utc_now() if now is None else now
    )
    audit_id = "audit-" + uuid.uuid4().hex
    details_json = json.dumps(
        sanitized_details,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    try:
        conn.execute(
            """
            INSERT INTO audit_events(
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
                details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                timestamp_value,
                user_id,
                actor,
                action_value,
                target_type_value,
                target_id_value,
                outcome_value,
                peer_ip_value,
                correlation_value,
                details_json,
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return AuditEvent(
        audit_id=audit_id,
        timestamp=timestamp_value,
        action=action_value,
        outcome=outcome_value,
        actor_user_id=user_id,
        actor_type=actor,
        target_type=target_type_value,
        target_id=target_id_value,
        peer_ip=peer_ip_value,
        correlation_id=correlation_value,
        details=sanitized_details,
    )
