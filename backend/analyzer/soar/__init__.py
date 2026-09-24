"""Safe Analyzer-side SOAR response primitives.

Endpoint-side response is deliberately not implemented: Collector command
delivery is not authenticated or designed for remote administration.
"""

from .engine import (
    ApprovalDeniedError,
    RecoveryDeniedError,
    SoarEngine,
)

__all__ = [
    "ApprovalDeniedError",
    "RecoveryDeniedError",
    "SoarEngine",
]
