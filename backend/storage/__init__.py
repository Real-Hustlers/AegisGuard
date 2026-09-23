"""Persistence primitives for AegisGuard Enterprise."""

from .audit_log import (
    AuditValidationError,
    record_audit_event,
    sanitize_audit_details,
)
from .audit_integrity import (
    AuditIntegrityError,
    verify_audit_chain,
)
from .audit_query import (
    AuditQueryError,
    query_audit_events,
)
from .migrations import (
    LATEST_PLATFORM_SCHEMA_VERSION,
    ensure_platform_schema,
    get_platform_schema_version,
)

__all__ = [
    "AuditIntegrityError",
    "AuditQueryError",
    "AuditValidationError",
    "LATEST_PLATFORM_SCHEMA_VERSION",
    "ensure_platform_schema",
    "get_platform_schema_version",
    "query_audit_events",
    "record_audit_event",
    "sanitize_audit_details",
    "verify_audit_chain",
]
