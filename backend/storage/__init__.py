"""Persistence primitives for AegisGuard Enterprise."""

from .migrations import (
    LATEST_PLATFORM_SCHEMA_VERSION,
    ensure_platform_schema,
    get_platform_schema_version,
)

__all__ = [
    "LATEST_PLATFORM_SCHEMA_VERSION",
    "ensure_platform_schema",
    "get_platform_schema_version",
]
