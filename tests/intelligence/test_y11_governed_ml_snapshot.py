from backend.analyzer.intelligence import build_intelligence_snapshot
from backend.analyzer.ml import MLEngine


class FakeModel:
    def __init__(self, encoded=1, probabilities=(0.05, 0.95)):
        self.encoded = encoded
        self.probabilities = probabilities

    def predict(self, frame):
        return [self.encoded]

    def predict_proba(self, frame):
        return [self.probabilities]


class FakeEncoder:
    def __init__(self, label):
        self.label = label

    def inverse_transform(self, values):
        return [self.label for _ in values]


def record(
    n,
    event_type,
    *,
    minute=0,
    severity="HIGH",
):
    return {
        "log_id": f"Y11-{n:03d}",
        "timestamp": f"2026-09-23T10:{minute:02d}:00Z",
        "event_type": event_type,
        "severity": severity,
        "hostname": "Y11-HOST",
        "source_ip": "10.0.0.5",
        "destination_ip": "10.0.0.10",
        "user": "alice",
        "process": "powershell.exe",
        "file_path": None,
        "raw_log": event_type,
        "ml_prediction": None,
        "ml_confidence": None,
        "threat_level": severity,
        "threat_score": 80,
        "threat_category": "Test",
    }


def engine(label="BRUTE_FORCE"):
    return MLEngine(
        model=FakeModel(),
        encoder=FakeEncoder(label),
        model_name="aegis-threat-classifier",
        model_version="1.0.0",
    )


def test_snapshot_without_governed_engine_preserves_existing_behavior():
    snapshot = build_intelligence_snapshot([
        record(1, "FAILED_LOGIN"),
    ])

    assert snapshot["detection_counts"]["ML"] == 0
    assert snapshot["findings"]["ml"] == []
    assert snapshot["governance"]["governed_ml_findings_available"] is False


def test_promoted_governed_engine_emits_real_ml_finding():
    snapshot = build_intelligence_snapshot(
        [
            record(1, "FAILED_LOGIN", minute=0),
            record(2, "FAILED_LOGIN", minute=1),
            record(3, "FAILED_LOGIN", minute=2),
        ],
        ml_engine=engine("BRUTE_FORCE"),
    )

    assert snapshot["detection_counts"]["ML"] == 1

    finding = snapshot["findings"]["ml"][0]

    assert finding["detection_type"] == "ML"
    assert finding["model_version"] == "1.0.0"
    assert finding["feature_schema_version"] == "legacy-18-v1"
    assert finding["prediction_source"] == "model:aegis-threat-classifier"

    assert snapshot["governance"]["governed_ml_findings_available"] is True


def test_normal_governed_prediction_does_not_create_detection():
    snapshot = build_intelligence_snapshot(
        [
            record(
                1,
                "LOGON_SUCCESS",
                severity="INFO",
            ),
        ],
        ml_engine=engine("NORMAL"),
    )

    assert snapshot["detection_counts"]["ML"] == 0
    assert snapshot["findings"]["ml"] == []

    # The governed engine was available even though it emitted no threat.
    assert snapshot["governance"]["governed_ml_findings_available"] is True


def test_governed_ml_and_legacy_telemetry_remain_separate():
    item = record(1, "FAILED_LOGIN")
    item["ml_prediction"] = "BRUTE_FORCE"
    item["ml_confidence"] = 96.0

    snapshot = build_intelligence_snapshot(
        [item],
        ml_engine=engine("BRUTE_FORCE"),
    )

    assert snapshot["detection_counts"]["ML"] == 1
    assert len(snapshot["findings"]["ml"]) == 1

    telemetry = snapshot["legacy_ml_telemetry"]

    assert telemetry["sample_count"] == 1
    assert telemetry["model_identity_available"] is False
    assert telemetry["governed_detection_findings_available"] is False
