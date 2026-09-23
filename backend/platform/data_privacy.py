"""Data-security and privacy primitives for AegisGuard Enterprise.

S7-A establishes one conservative classification/redaction contract. It does
not alter detection, ML, correlation, MITRE, incident semantics, or forensic
event retention.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Mapping


REDACTED = "[REDACTED]"


class DataSensitivity(str, Enum):
    """Coarse enterprise data classification used by S7 controls."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    SECURITY_SENSITIVE = "SECURITY_SENSITIVE"
    SECRET = "SECRET"


_SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "credential",
    "authorization",
    "cookie",
    "csrf",
    "private_key",
    "client_key",
    "session_token",
    "access_token",
    "refresh_token",
    "api_key",
    "bearer_token",
)

_SECURITY_SENSITIVE_FIELDS = frozenset({
    "raw_log",
    "payload_json",
    "normalized_json",
    "username",
    "user_name",
    "user",
    "hostname",
    "machine_id",
    "source_ip",
    "destination_ip",
    "primary_ip",
    "peer_ip",
    "file_path",
    "process",
    "process_name",
    "user_agent",
    "note",
    "body",
    "description",
    "incident_report",
    "ip",
    "device",
    "event",
    "message",
    "target_ip",
    "hostnames",
    "source_ips",
    "destination_ips",
    "users",
    "processes",
    "file_paths",
    "related_entities",
    "notes",
    "evidence_references",
    "resolution_summary",
    "soar_allowlist",
})

_PUBLIC_FIELDS = frozenset({
    "status",
    "state",
    "severity",
    "event_count",
    "record_id",
    "max_record_id",
    "attempts",
})


def _normalized_key(name: Any) -> str:
    return str(name or "").strip().lower().replace("-", "_")


def classify_field(name: Any) -> DataSensitivity:
    """Classify a field by its data-handling sensitivity."""

    key = _normalized_key(name)
    if any(part in key for part in _SECRET_KEY_PARTS):
        return DataSensitivity.SECRET
    if key in _SECURITY_SENSITIVE_FIELDS:
        return DataSensitivity.SECURITY_SENSITIVE
    if key in _PUBLIC_FIELDS:
        return DataSensitivity.PUBLIC
    return DataSensitivity.INTERNAL


def _redact_value(
    value: Any,
    *,
    redact_security_sensitive: bool,
) -> Any:
    if isinstance(value, Mapping):
        return redact_sensitive_mapping(
            value,
            redact_security_sensitive=redact_security_sensitive,
        )
    if isinstance(value, (list, tuple)):
        return [
            _redact_value(
                item,
                redact_security_sensitive=redact_security_sensitive,
            )
            for item in value
        ]
    return value


def redact_sensitive_mapping(
    value: Mapping[str, Any],
    *,
    redact_security_sensitive: bool = False,
) -> dict[str, Any]:
    """Redact secret-bearing keys recursively.

    Security telemetry is retained by default because SOC workflows require
    it. Callers may explicitly redact SECURITY_SENSITIVE fields for lower
    trust outputs such as future exports.
    """

    result: dict[str, Any] = {}
    for key, child in value.items():
        sensitivity = classify_field(key)
        key_text = str(key)

        if sensitivity is DataSensitivity.SECRET:
            result[key_text] = REDACTED
            continue

        if (
            redact_security_sensitive
            and sensitivity is DataSensitivity.SECURITY_SENSITIVE
        ):
            result[key_text] = REDACTED
            continue

        result[key_text] = _redact_value(
            child,
            redact_security_sensitive=redact_security_sensitive,
        )

    return result


_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)

_AUTH_HEADER_RE = re.compile(
    r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+",
    re.IGNORECASE,
)

_KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|secret|credential|authorization|csrf|"
    r"private_key|client_key|session_token|access_token|"
    r"refresh_token|api_key|bearer_token"
    r")\s*[:=]\s*([^\s,;]+)"
)


def redact_sensitive_text(value: Any, *, max_length: int = 2048) -> str:
    """Remove obvious credentials/secrets from diagnostic text."""

    text = str(value)
    text = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    text = _AUTH_HEADER_RE.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _KEY_VALUE_SECRET_RE.sub(
        lambda m: f"{m.group(1)}={REDACTED}",
        text,
    )

    limit = int(max_length)
    if limit <= 0:
        raise ValueError("max_length must be greater than zero")
    if len(text) > limit:
        return text[:limit] + "...[TRUNCATED]"
    return text
