"""Stable cross-module contracts for AegisGuard Enterprise.

These contracts define data exchanged between Saran-owned platform services and
Yogendiran-owned intelligence/UI modules. They intentionally contain no
detection, ML, correlation, or frontend behavior.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Role(str, Enum):
    ADMINISTRATOR = "ADMINISTRATOR"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class IncidentLifecycleStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CONTAINMENT = "CONTAINMENT"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class ResponseActionStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SIMULATED = "SIMULATED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


def _require(value: str, field_name: str) -> None:
    if not str(value or "").strip():
        raise ValueError(f"{field_name} must not be empty")


@dataclass(frozen=True)
class CanonicalEvent:
    event_id: str
    observed_at: str
    event_type: str
    collector_id: Optional[str] = None
    asset_id: Optional[str] = None
    severity: Optional[str] = None
    user_name: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None
    raw_log_hash: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require(self.event_id, "event_id")
        _require(self.observed_at, "observed_at")
        _require(self.event_type, "event_type")


@dataclass(frozen=True)
class CollectorIdentity:
    collector_id: str
    hostname: str
    version: Optional[str] = None
    status: str = "ENROLLED"
    credential_fingerprint: Optional[str] = None

    def __post_init__(self) -> None:
        _require(self.collector_id, "collector_id")
        _require(self.hostname, "hostname")


@dataclass(frozen=True)
class Asset:
    asset_id: str
    hostname: str
    collector_id: Optional[str] = None
    os: Optional[str] = None
    primary_ip: Optional[str] = None

    def __post_init__(self) -> None:
        _require(self.asset_id, "asset_id")
        _require(self.hostname, "hostname")


@dataclass(frozen=True)
class Incident:
    incident_id: str
    title: str
    lifecycle_status: IncidentLifecycleStatus = IncidentLifecycleStatus.OPEN
    severity: Optional[str] = None
    assigned_user_id: Optional[str] = None
    opened_at: Optional[str] = None
    updated_at: Optional[str] = None

    def __post_init__(self) -> None:
        _require(self.incident_id, "incident_id")
        _require(self.title, "title")


@dataclass(frozen=True)
class AuditEvent:
    audit_id: str
    timestamp: str
    action: str
    outcome: str
    actor_user_id: Optional[str] = None
    actor_type: str = "SYSTEM"
    target_type: Optional[str] = None
    target_id: Optional[str] = None
    peer_ip: Optional[str] = None
    correlation_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require(self.audit_id, "audit_id")
        _require(self.timestamp, "timestamp")
        _require(self.action, "action")
        _require(self.outcome, "outcome")


@dataclass(frozen=True)
class ResponseAction:
    action_id: str
    incident_id: str
    action_type: str
    target: str
    requested_by_user_id: Optional[str] = None
    status: ResponseActionStatus = ResponseActionStatus.PENDING
    simulation_result: Optional[str] = None

    def __post_init__(self) -> None:
        _require(self.action_id, "action_id")
        _require(self.incident_id, "incident_id")
        _require(self.action_type, "action_type")
        _require(self.target, "target")
