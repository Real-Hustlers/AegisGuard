import json
import sqlite3

import pytest

from backend.analyzer.intelligence import (
    INTELLIGENCE_SNAPSHOT_VERSION,
    MAX_EVENT_LIMIT,
    build_intelligence_snapshot,
    get_intelligence_snapshot,
    normalize_event_limit,
)


def event(
    n,
    event_type,
    *,
    minute,
    hostname="Y8-HOST",
    user="alice",
    source_ip="10.0.0.5",
    severity="HIGH",
    ml_prediction=None,
    ml_confidence=None,
):
    return {
        "log_id": f"EVT-Y8-{n:03d}",
        "timestamp": f"2026-09-22T10:{minute:02d}:00Z",
        "event_type": event_type,
        "severity": severity,
        "hostname": hostname,
        "source_ip": source_ip,
        "destination_ip": "10.0.0.10",
        "user": user,
        "process": "powershell.exe",
        "file_path": None,
        "raw_log": f"event {n}",
        "ml_prediction": ml_prediction,
        "ml_confidence": ml_confidence,
        "threat_level": severity,
        "threat_score": 80,
        "threat_category": "Test",
    }


def multi_stage_records():
    return [
        event(1, "FAILED_LOGIN", minute=0),
        event(2, "FAILED_LOGIN", minute=1),
        event(3, "FAILED_LOGIN", minute=2),
        event(4, "LOGON_SUCCESS", minute=3, severity="INFO"),
        event(5, "USER_CREATED", minute=4),
        event(6, "PASSWORD_CHANGED", minute=5),
        event(7, "LOGON_SUCCESS", minute=6, severity="INFO"),
    ]


def test_snapshot_version_is_explicit():
    assert INTELLIGENCE_SNAPSHOT_VERSION == "intelligence-snapshot-v1"


def test_empty_snapshot_is_read_only_and_serializable():
    snapshot = build_intelligence_snapshot([])
    assert snapshot["detection_counts"] == {
        "RULE": 0,
        "ML": 0,
        "CORRELATION": 0,
    }
    assert snapshot["attack_stories"] == []
    assert snapshot["governance"]["read_only"] is True
    assert snapshot["governance"]["writes_database"] is False
    json.dumps(snapshot)


def test_rule_engine_findings_are_exposed_as_real_contracts():
    snapshot = build_intelligence_snapshot([
        event(1, "FAILED_LOGIN", minute=0),
    ])
    assert snapshot["detection_counts"]["RULE"] == 1
    finding = snapshot["findings"]["rule"][0]
    assert finding["detection_type"] == "RULE"
    assert finding["rule_id"] == "AG-RULE-AUTH-001"
    assert finding["source_engine"] == "rule-engine-v1"


def test_correlation_engine_findings_are_exposed():
    snapshot = build_intelligence_snapshot(multi_stage_records())
    ids = {
        finding["correlation_id"]
        for finding in snapshot["findings"]["correlation"]
    }
    assert "AG-CORR-AUTH-001A" in ids
    assert "AG-CORR-AUTH-001B" in ids
    assert "AG-CORR-PERSIST-001" in ids


def test_multi_stage_records_build_real_y6_attack_story():
    snapshot = build_intelligence_snapshot(multi_stage_records())
    assert snapshot["attack_stories"]
    story = snapshot["attack_stories"][0]
    assert story["candidate_id"].startswith("CAND-STORY-")
    assert "CREDENTIAL_ACCESS" in story["metadata"]["attack_stages"]
    assert "PERSISTENCE" in story["metadata"]["attack_stages"]
    assert len(story["metadata"]["timeline"]) >= 2


def test_mitre_coverage_is_deduplicated_from_real_findings():
    snapshot = build_intelligence_snapshot(multi_stage_records())
    technique_ids = {
        item["technique_id"] for item in snapshot["mitre_coverage"]
    }
    assert "T1110" in technique_ids
    assert "T1136" in technique_ids


def test_legacy_ml_is_telemetry_not_governed_ml_finding():
    snapshot = build_intelligence_snapshot([
        event(
            1,
            "FAILED_LOGIN",
            minute=0,
            ml_prediction="BRUTE_FORCE",
            ml_confidence=96.0,
        ),
    ])
    assert snapshot["detection_counts"]["ML"] == 0
    assert snapshot["findings"]["ml"] == []
    telemetry = snapshot["legacy_ml_telemetry"]
    assert telemetry["sample_count"] == 1
    assert telemetry["average_confidence"] == 96.0
    assert telemetry["model_identity_available"] is False
    assert telemetry["governed_detection_findings_available"] is False


def test_ml_telemetry_uses_legacy_percent_confidence_unit():
    snapshot = build_intelligence_snapshot([
        event(1, "FAILED_LOGIN", minute=0, ml_prediction="BRUTE_FORCE", ml_confidence=96),
        event(2, "LOGON_SUCCESS", minute=1, ml_prediction="NORMAL", ml_confidence=99),
    ])
    telemetry = snapshot["legacy_ml_telemetry"]
    assert telemetry["confidence_unit"] == "percent_0_100"
    assert telemetry["average_confidence"] == 97.5
    assert telemetry["non_normal_count"] == 1


def test_invalid_event_is_reported_without_breaking_snapshot():
    snapshot = build_intelligence_snapshot([
        {"log_id": "BAD-1", "timestamp": "", "event_type": ""},
    ])
    assert snapshot["scope"]["rejected_events"]
    assert snapshot["detection_counts"]["RULE"] == 0


def test_invalid_finding_timestamp_does_not_break_attack_story_building():
    record = event(1, "FAILED_LOGIN", minute=0)
    record["timestamp"] = "not-a-time"
    snapshot = build_intelligence_snapshot([record])
    assert snapshot["attack_stories"] == []
    assert snapshot["detection_counts"]["RULE"] == 1


def test_event_limit_validation_and_cap():
    assert normalize_event_limit(None) > 0
    assert normalize_event_limit(MAX_EVENT_LIMIT + 100) == MAX_EVENT_LIMIT
    with pytest.raises(ValueError, match="at least 1"):
        normalize_event_limit(0)
    with pytest.raises(ValueError, match="integer"):
        normalize_event_limit("abc")


def test_scope_reports_truncation():
    snapshot = build_intelligence_snapshot(
        [event(1, "LOGON_SUCCESS", minute=0)],
        total_events=20,
        event_limit=1,
    )
    assert snapshot["scope"]["events_analyzed"] == 1
    assert snapshot["scope"]["total_events"] == 20
    assert snapshot["scope"]["truncated"] is True


def test_sqlite_reader_is_read_only_and_closes_connection():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE security_logs (
            log_id TEXT,
            timestamp TEXT,
            event_type TEXT,
            severity TEXT,
            hostname TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            user TEXT,
            process TEXT,
            file_path TEXT,
            raw_log TEXT,
            ml_prediction TEXT,
            ml_confidence REAL,
            threat_level TEXT,
            threat_score INTEGER,
            threat_category TEXT
        )
        """
    )
    for record in multi_stage_records():
        connection.execute(
            """
            INSERT INTO security_logs VALUES (
                :log_id, :timestamp, :event_type, :severity, :hostname,
                :source_ip, :destination_ip, :user, :process, :file_path,
                :raw_log, :ml_prediction, :ml_confidence, :threat_level,
                :threat_score, :threat_category
            )
            """,
            record,
        )
    connection.commit()

    class NonClosingConnection:
        def __init__(self, inner):
            self.inner = inner
            self.closed = False

        def execute(self, *args, **kwargs):
            return self.inner.execute(*args, **kwargs)

        def close(self):
            self.closed = True

    wrapped = NonClosingConnection(connection)
    snapshot = get_intelligence_snapshot(lambda: wrapped, event_limit=5)

    assert wrapped.closed is True
    assert snapshot["scope"]["events_analyzed"] == 5
    assert snapshot["scope"]["total_events"] == 7
    assert snapshot["scope"]["truncated"] is True
    assert connection.execute("SELECT COUNT(*) FROM security_logs").fetchone()[0] == 7
    connection.close()
