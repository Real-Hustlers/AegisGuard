"""Compatibility adapters between legacy AegisGuard payloads and Y1 contracts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .contracts import CanonicalEvent, DetectionFinding, DetectionType, Severity


_SEVERITY_MAP = {
    "INFO": Severity.INFO,
    "INFORMATION": Severity.INFO,
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
    "CRITICAL": Severity.CRITICAL,
}


def normalize_severity(value: Any) -> Severity:
    """Normalize legacy severity strings into the shared severity enum."""

    key = str(value or "INFO").strip().upper()
    return _SEVERITY_MAP.get(key, Severity.INFO)


def canonical_event_from_legacy(record: Mapping[str, Any]) -> CanonicalEvent:
    """Create a CanonicalEvent from the existing normalized-log dictionary."""

    event_id = (
        record.get("event_id")
        or record.get("log_id")
        or record.get("record_id")
    )
    if event_id is None:
        raise ValueError("legacy event requires event_id, log_id, or record_id")

    known_fields = {
        "event_id",
        "log_id",
        "record_id",
        "timestamp",
        "event_type",
        "severity",
        "hostname",
        "source_ip",
        "destination_ip",
        "user",
        "process",
        "file_path",
        "raw_event",
        "raw_log",
    }

    attributes = {
        key: value
        for key, value in record.items()
        if key not in known_fields
    }

    return CanonicalEvent(
        event_id=str(event_id),
        timestamp=str(record.get("timestamp") or ""),
        event_type=str(record.get("event_type") or ""),
        severity=normalize_severity(record.get("severity")).value,
        hostname=record.get("hostname"),
        source_ip=record.get("source_ip"),
        destination_ip=record.get("destination_ip"),
        user=record.get("user"),
        process=record.get("process"),
        file_path=record.get("file_path"),
        raw_event=record.get("raw_event") or record.get("raw_log"),
        attributes=attributes,
    )


def rule_finding_from_legacy_classification(
    record: Mapping[str, Any],
    *,
    finding_id: str,
    rule_id: str,
    name: str,
    reason: str,
    confidence: float = 1.0,
) -> DetectionFinding:
    """Represent deterministic legacy classification output as a RULE finding.

    This adapter deliberately does not infer that ``ml_prediction`` means ML.
    It is intended for known deterministic classifications while the legacy
    classifier is incrementally separated in Phase Y2.
    """

    event = canonical_event_from_legacy(record)

    return DetectionFinding(
        finding_id=finding_id,
        event_ids=(event.event_id,),
        detection_type=DetectionType.RULE,
        name=name,
        severity=normalize_severity(
            record.get("threat_level") or record.get("severity")
        ),
        confidence=confidence,
        reason=reason,
        timestamp=event.timestamp,
        prediction_source=f"rule:{rule_id}",
        rule_id=rule_id,
        source_engine="legacy-classifier-adapter",
        evidence=(
            {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "legacy_prediction": record.get("ml_prediction"),
                "legacy_threat_score": record.get("threat_score"),
            },
        ),
    )
