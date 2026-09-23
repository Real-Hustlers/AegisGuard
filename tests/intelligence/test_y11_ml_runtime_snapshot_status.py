from backend.analyzer.intelligence import (
    GovernedMLRuntime,
    GovernedMLRuntimeStatus,
    build_intelligence_snapshot,
)
from backend.analyzer.ml import MLEngine


class FakeModel:
    def __init__(self, encoded=1):
        self.encoded = encoded

    def predict(self, frame):
        return [self.encoded]

    def predict_proba(self, frame):
        return [[0.05, 0.95]]


class FakeEncoder:
    def __init__(self, label="BRUTE_FORCE"):
        self.label = label

    def inverse_transform(self, values):
        return [self.label for _ in values]


def record(n, event_type, minute):
    return {
        "log_id": f"Y11-RUNTIME-{n}",
        "timestamp": f"2026-09-23T10:{minute:02d}:00Z",
        "event_type": event_type,
        "severity": "HIGH",
        "hostname": "Y11-RUNTIME-HOST",
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.10",
        "user": "alice",
        "process": "powershell.exe",
        "file_path": None,
        "raw_log": event_type,
        "ml_prediction": None,
        "ml_confidence": None,
        "threat_level": "HIGH",
        "threat_score": 80,
        "threat_category": "Test",
    }


def engine():
    return MLEngine(
        model=FakeModel(),
        encoder=FakeEncoder(),
        model_name="aegis-threat-classifier",
        model_version="1.0.0",
    )


def credential_records():
    return [
        record(1, "FAILED_LOGIN", 0),
        record(2, "FAILED_LOGIN", 1),
        record(3, "FAILED_LOGIN", 2),
    ]


def test_snapshot_reports_runtime_unavailable_when_not_configured():
    snapshot = build_intelligence_snapshot(
        credential_records()
    )

    runtime = snapshot["governed_ml_runtime"]

    assert runtime["status"] == "UNAVAILABLE"
    assert runtime["available"] is False
    assert runtime["model_name"] is None
    assert runtime["model_version"] is None

    assert snapshot["detection_counts"]["ML"] == 0


def test_available_runtime_executes_governed_ml():
    ml_engine = engine()

    runtime = GovernedMLRuntime(
        status=GovernedMLRuntimeStatus.AVAILABLE,
        available=True,
        model_name=ml_engine.model_name,
        model_version=ml_engine.model_version,
        feature_schema_version=ml_engine.feature_schema_version,
        engine=ml_engine,
    )

    snapshot = build_intelligence_snapshot(
        credential_records(),
        ml_runtime=runtime,
    )

    assert snapshot["detection_counts"]["ML"] == 1
    assert len(snapshot["findings"]["ml"]) == 1

    state = snapshot["governed_ml_runtime"]

    assert state["status"] == "AVAILABLE"
    assert state["available"] is True
    assert state["model_name"] == "aegis-threat-classifier"
    assert state["model_version"] == "1.0.0"

    assert (
        snapshot["governance"]
        ["governed_ml_findings_available"]
        is True
    )


def test_unavailable_ml_does_not_disable_rule_or_correlation():
    runtime = GovernedMLRuntime(
        status=GovernedMLRuntimeStatus.UNAVAILABLE,
        available=False,
        model_name="aegis-threat-classifier",
        reason="no promoted model",
    )

    snapshot = build_intelligence_snapshot(
        credential_records(),
        ml_runtime=runtime,
    )

    assert snapshot["detection_counts"]["ML"] == 0
    assert snapshot["detection_counts"]["RULE"] > 0
    assert snapshot["detection_counts"]["CORRELATION"] > 0

    correlation_ids = {
        finding["correlation_id"]
        for finding in snapshot["findings"]["correlation"]
    }

    assert "AG-CORR-AUTH-001A" in correlation_ids

    state = snapshot["governed_ml_runtime"]

    assert state["status"] == "UNAVAILABLE"
    assert state["reason"] == "no promoted model"


def test_degraded_ml_does_not_disable_rule_or_correlation():
    runtime = GovernedMLRuntime(
        status=GovernedMLRuntimeStatus.DEGRADED,
        available=False,
        model_name="aegis-threat-classifier",
        model_version="1.0.0",
        feature_schema_version="legacy-18-v1",
        reason="model artifact SHA-256 mismatch",
    )

    snapshot = build_intelligence_snapshot(
        credential_records(),
        ml_runtime=runtime,
    )

    assert snapshot["detection_counts"]["ML"] == 0
    assert snapshot["detection_counts"]["RULE"] > 0
    assert snapshot["detection_counts"]["CORRELATION"] > 0

    state = snapshot["governed_ml_runtime"]

    assert state["status"] == "DEGRADED"
    assert state["available"] is False
    assert "SHA-256 mismatch" in state["reason"]

    assert (
        snapshot["governance"]
        ["governed_ml_findings_available"]
        is False
    )
