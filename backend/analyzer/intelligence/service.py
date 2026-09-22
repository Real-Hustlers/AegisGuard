"""Read-only intelligence snapshot construction for AegisGuard Enterprise.

Y8 bridges persisted analyzer events into the pure Y2/Y5/Y6 intelligence
contracts without changing persistence, incident lifecycle, or response state.

Legacy ``ml_prediction``/``ml_confidence`` columns are intentionally reported
as legacy telemetry rather than converted into governed Y3 ML findings because
the legacy rows do not persist model/version/feature-schema identity.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping

from backend.analyzer.correlation import build_attack_stories
from backend.analyzer.correlation.engine import CorrelationEngine
from backend.analyzer.detection.adapters import canonical_event_from_legacy
from backend.analyzer.detection.contracts import DetectionFinding
from backend.analyzer.detection.rule_engine import RuleEngine


INTELLIGENCE_SNAPSHOT_VERSION = "intelligence-snapshot-v1"
DEFAULT_EVENT_LIMIT = 1000
MAX_EVENT_LIMIT = 5000


def normalize_event_limit(value: int | str | None) -> int:
    if value is None:
        return DEFAULT_EVENT_LIMIT
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("event_limit must be an integer") from exc
    if parsed < 1:
        raise ValueError("event_limit must be at least 1")
    return min(parsed, MAX_EVENT_LIMIT)


def _parseable_timestamp(value: object) -> bool:
    try:
        datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        return True
    except (TypeError, ValueError):
        return False


def _legacy_ml_telemetry(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    predictions: Counter[str] = Counter()
    confidences: list[float] = []

    for record in records:
        prediction = str(record.get("ml_prediction") or "").strip().upper()
        if prediction:
            predictions[prediction] += 1

        confidence = record.get("ml_confidence")
        if confidence not in (None, ""):
            try:
                confidences.append(float(confidence))
            except (TypeError, ValueError):
                pass

    sample_count = sum(predictions.values())
    non_normal_count = sum(
        count for label, count in predictions.items() if label != "NORMAL"
    )
    average_confidence = (
        round(sum(confidences) / len(confidences), 2)
        if confidences
        else None
    )

    return {
        "source": "legacy_security_logs",
        "governed_detection_findings_available": False,
        "model_identity_available": False,
        "model_version": None,
        "feature_schema_version": None,
        "confidence_unit": "percent_0_100",
        "sample_count": sample_count,
        "non_normal_count": non_normal_count,
        "average_confidence": average_confidence,
        "predictions": [
            {"prediction": label, "count": count}
            for label, count in sorted(
                predictions.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ],
        "limitation": (
            "Persisted legacy ML rows do not contain governed Y3 model identity, "
            "model version, or feature-schema identity, so they are telemetry only."
        ),
    }


def _mitre_coverage(findings: Iterable[DetectionFinding]) -> list[dict[str, str]]:
    coverage: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for finding in findings:
        for mapping in finding.mitre:
            key = (mapping.technique_id, mapping.technique, mapping.tactic)
            if key in seen:
                continue
            seen.add(key)
            coverage.append(mapping.to_dict())

    return coverage


def build_intelligence_snapshot(
    records: Iterable[Mapping[str, Any]],
    *,
    total_events: int | None = None,
    event_limit: int | None = None,
) -> dict[str, Any]:
    supplied = tuple(dict(record) for record in records)

    canonical_events = []
    rejected_events = []
    for record in supplied:
        try:
            canonical_events.append(canonical_event_from_legacy(record))
        except (TypeError, ValueError) as exc:
            rejected_events.append({
                "log_id": record.get("log_id"),
                "reason": str(exc),
            })

    rule_findings = RuleEngine().detect_many(canonical_events)
    correlation_findings = CorrelationEngine().correlate(canonical_events)
    all_findings = tuple(rule_findings) + tuple(correlation_findings)

    story_eligible = tuple(
        finding
        for finding in all_findings
        if _parseable_timestamp(finding.timestamp)
    )
    attack_stories = build_attack_stories(story_eligible)

    observed_total = len(supplied) if total_events is None else int(total_events)
    applied_limit = len(supplied) if event_limit is None else int(event_limit)

    return {
        "snapshot_version": INTELLIGENCE_SNAPSHOT_VERSION,
        "scope": {
            "source": "security_logs",
            "event_limit": applied_limit,
            "events_analyzed": len(supplied),
            "total_events": observed_total,
            "truncated": observed_total > len(supplied),
            "rejected_events": rejected_events,
        },
        "detection_counts": {
            "RULE": len(rule_findings),
            "ML": 0,
            "CORRELATION": len(correlation_findings),
        },
        "findings": {
            "rule": [finding.to_dict() for finding in rule_findings],
            "ml": [],
            "correlation": [
                finding.to_dict() for finding in correlation_findings
            ],
        },
        "mitre_coverage": _mitre_coverage(all_findings),
        "attack_stories": [
            candidate.to_dict() for candidate in attack_stories
        ],
        "legacy_ml_telemetry": _legacy_ml_telemetry(supplied),
        "governance": {
            "read_only": True,
            "writes_database": False,
            "changes_incident_lifecycle": False,
            "executes_response_actions": False,
            "governed_ml_findings_available": False,
        },
    }


def get_intelligence_snapshot(
    get_connection: Callable[[], Any],
    *,
    event_limit: int | str | None = None,
) -> dict[str, Any]:
    limit = normalize_event_limit(event_limit)
    conn = get_connection()
    try:
        total_events = int(
            conn.execute("SELECT COUNT(*) FROM security_logs").fetchone()[0]
        )

        rows = conn.execute(
            """
            SELECT
                log_id,
                timestamp,
                event_type,
                severity,
                hostname,
                source_ip,
                destination_ip,
                user,
                process,
                file_path,
                raw_log,
                ml_prediction,
                ml_confidence,
                threat_level,
                threat_score,
                threat_category
            FROM security_logs
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()

    records = [dict(row) for row in reversed(rows)]

    return build_intelligence_snapshot(
        records,
        total_events=total_events,
        event_limit=limit,
    )
