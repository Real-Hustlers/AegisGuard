"""Persistence primitives for AegisGuard Enterprise."""

from .audit_log import (
    AuditValidationError,
    record_audit_event,
    sanitize_audit_details,
)
from .migrations import (
    LATEST_PLATFORM_SCHEMA_VERSION,
    ensure_platform_schema,
    get_platform_schema_version,
)

__all__ = [
    "AuditValidationError",
    "LATEST_PLATFORM_SCHEMA_VERSION",
    "ensure_platform_schema",
    "get_platform_schema_version",
    "record_audit_event",
    "sanitize_audit_details",
]
