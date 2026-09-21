"""Stable shared intelligence contracts for AegisGuard Enterprise.

These contracts separate security evidence, detections, ML predictions,
MITRE ATT&CK mappings, and incident candidacy.  They intentionally contain
no persistence, Flask, collector, or response-engine dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


CONTRACT_VERSION = "1.0"


class DetectionType(str, Enum):
    """Origin of a detection finding."""

    RULE = "RULE"
    ML = "ML"
    CORRELATION = "CORRELATION"


class Severity(str, Enum):
    """Normalized finding/candidate severity."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def _require_text(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _require_confidence(value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("confidence must be numeric")
    if not 0.0 <= float(value) <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0")


def _enum_value(value: Enum | str) -> str:
    return value.value if isinstance(value, Enum) else str(value)


@dataclass(frozen=True)
class MITREMapping:
    """One normalized MITRE ATT&CK technique mapping."""

    technique_id: str
    technique: str
    tactic: str

    def __post_init__(self) -> None:
        _require_text(self.technique_id, "technique_id")
        _require_text(self.technique, "technique")
        _require_text(self.tactic, "tactic")

    def to_dict(self) -> dict[str, str]:
        return {
            "technique_id": self.technique_id,
            "technique": self.technique,
            "tactic": self.tactic,
        }


@dataclass(frozen=True)
class CanonicalEvent:
    """Normalized security event consumed by detection engines.

    ``attributes`` preserves source-specific normalized fields that are not
    part of the stable first-class contract. ``raw_event`` is optional because
    deployments may retain raw evidence by reference instead of embedding it.
    """

    event_id: str
    timestamp: str
    event_type: str
    severity: str = "INFO"
    hostname: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    user: str | None = None
    process: str | None = None
    file_path: str | None = None
    raw_event: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _require_text(self.event_id, "event_id")
        _require_text(self.timestamp, "timestamp")
        _require_text(self.event_type, "event_type")
        _require_text(self.severity, "severity")
        _require_text(self.schema_version, "schema_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "hostname": self.hostname,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "user": self.user,
            "process": self.process,
            "file_path": self.file_path,
            "raw_event": self.raw_event,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class MLPrediction:
    """Auditable output from an ML model before it becomes a finding.

    Confidence uses a unit interval: 0.0 means no model confidence and 1.0
    means maximum model confidence. Presentation layers may render it as a
    percentage, but persisted intelligence contracts stay unambiguous.
    """

    prediction: str
    confidence: float
    model_name: str
    model_version: str
    feature_schema_version: str
    prediction_source: str
    event_ids: tuple[str, ...]
    timestamp: str
    fallback_reason: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _require_text(self.prediction, "prediction")
        _require_confidence(self.confidence)
        _require_text(self.model_name, "model_name")
        _require_text(self.model_version, "model_version")
        _require_text(self.feature_schema_version, "feature_schema_version")
        _require_text(self.prediction_source, "prediction_source")
        _require_text(self.timestamp, "timestamp")
        if not self.event_ids:
            raise ValueError("event_ids must contain at least one event id")
        for event_id in self.event_ids:
            _require_text(event_id, "event_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "prediction": self.prediction,
            "confidence": float(self.confidence),
            "model_name": self.model_name,
            "model_version": self.model_version,
            "feature_schema_version": self.feature_schema_version,
            "prediction_source": self.prediction_source,
            "event_ids": list(self.event_ids),
            "timestamp": self.timestamp,
            "fallback_reason": self.fallback_reason,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class DetectionFinding:
    """Stable output contract shared by rule, ML, and correlation engines."""

    finding_id: str
    event_ids: tuple[str, ...]
    detection_type: DetectionType
    name: str
    severity: Severity
    confidence: float
    reason: str
    timestamp: str
    prediction_source: str
    evidence: tuple[Mapping[str, Any], ...] = ()
    mitre: tuple[MITREMapping, ...] = ()
    model_version: str | None = None
    source_engine: str | None = None
    rule_id: str | None = None
    feature_schema_version: str | None = None
    correlation_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _require_text(self.finding_id, "finding_id")
        if not self.event_ids:
            raise ValueError("event_ids must contain at least one event id")
        for event_id in self.event_ids:
            _require_text(event_id, "event_id")
        if not isinstance(self.detection_type, DetectionType):
            raise TypeError("detection_type must be a DetectionType")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        _require_text(self.name, "name")
        _require_confidence(self.confidence)
        _require_text(self.reason, "reason")
        _require_text(self.timestamp, "timestamp")
        _require_text(self.prediction_source, "prediction_source")
        _require_text(self.schema_version, "schema_version")
        if self.detection_type is DetectionType.ML:
            if self.model_version is None:
                raise ValueError("model_version is required for ML findings")
            _require_text(self.model_version, "model_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "event_ids": list(self.event_ids),
            "evidence": [dict(item) for item in self.evidence],
            "detection_type": _enum_value(self.detection_type),
            "name": self.name,
            "severity": _enum_value(self.severity),
            "confidence": float(self.confidence),
            "reason": self.reason,
            "mitre": [mapping.to_dict() for mapping in self.mitre],
            "model_version": self.model_version,
            "prediction_source": self.prediction_source,
            "timestamp": self.timestamp,
            "source_engine": self.source_engine,
            "rule_id": self.rule_id,
            "feature_schema_version": self.feature_schema_version,
            "correlation_id": self.correlation_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class IncidentCandidate:
    """Detection-layer request for incident creation.

    This is deliberately not the incident lifecycle model. Persistence,
    workflow state, ownership, approvals, and response governance remain the
    responsibility of the platform/incident backend.
    """

    candidate_id: str
    finding_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    name: str
    severity: Severity
    confidence: float
    reason: str
    timestamp: str
    mitre: tuple[MITREMapping, ...] = ()
    related_entities: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _require_text(self.candidate_id, "candidate_id")
        if not self.finding_ids:
            raise ValueError("finding_ids must contain at least one finding id")
        for finding_id in self.finding_ids:
            _require_text(finding_id, "finding_id")
        if not self.event_ids:
            raise ValueError("event_ids must contain at least one event id")
        for event_id in self.event_ids:
            _require_text(event_id, "event_id")
        _require_text(self.name, "name")
        if not isinstance(self.severity, Severity):
            raise TypeError("severity must be a Severity")
        _require_confidence(self.confidence)
        _require_text(self.reason, "reason")
        _require_text(self.timestamp, "timestamp")
        _require_text(self.schema_version, "schema_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "finding_ids": list(self.finding_ids),
            "event_ids": list(self.event_ids),
            "name": self.name,
            "severity": _enum_value(self.severity),
            "confidence": float(self.confidence),
            "reason": self.reason,
            "timestamp": self.timestamp,
            "mitre": [mapping.to_dict() for mapping in self.mitre],
            "related_entities": {
                key: list(values)
                for key, values in self.related_entities.items()
            },
            "metadata": dict(self.metadata),
        }
