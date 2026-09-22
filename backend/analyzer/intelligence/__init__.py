"""Read-only intelligence presentation services for AegisGuard Enterprise."""

from .service import (
    DEFAULT_EVENT_LIMIT,
    INTELLIGENCE_SNAPSHOT_VERSION,
    MAX_EVENT_LIMIT,
    build_intelligence_snapshot,
    get_intelligence_snapshot,
    normalize_event_limit,
)

__all__ = [
    "DEFAULT_EVENT_LIMIT",
    "INTELLIGENCE_SNAPSHOT_VERSION",
    "MAX_EVENT_LIMIT",
    "build_intelligence_snapshot",
    "get_intelligence_snapshot",
    "normalize_event_limit",
]
