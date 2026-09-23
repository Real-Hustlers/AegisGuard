import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from backend.analyzer.correlation import CorrelationEngine
from backend.analyzer.detection.contracts import CanonicalEvent
from backend.analyzer.ml import (
    ArtifactIntegrityError,
    EvaluationMetrics,
    FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
    MLEngine,
    ModelRegistry,
    fingerprint_training_data,
)


def event(
    n,
    event_type,
    minute=0,
    *,
    hostname="Y10-HOST",
    user="alice",
    source_ip="10.0.0.5",
):
    return CanonicalEvent(
        event_id=f"Y10-{n:03d}",
        timestamp=f"2026-09-23T10:{minute:02d}:00Z",
        event_type=event_type,
        severity="HIGH",
        hostname=hostname,
        user=user,
        source_ip=source_ip,
    )


def correlation_findings(events):
    return {
        finding.correlation_id: finding
        for finding in CorrelationEngine().correlate(events)
    }


def test_failed_login_threshold_does_not_mix_users_or_sources():
    findings = correlation_findings([
        event(1, "FAILED_LOGIN", 0, user="alice", source_ip="10.0.0.5"),
        event(2, "FAILED_LOGIN", 1, user="alice", source_ip="10.0.0.5"),
        event(3, "FAILED_LOGIN", 2, user="alice", source_ip="10.0.0.9"),
        event(4, "FAILED_LOGIN", 3, user="bob", source_ip="10.0.0.5"),
    ])

    assert "AG-CORR-AUTH-001A" not in findings
    assert "AG-CORR-AUTH-001B" not in findings


def test_success_after_five_minute_window_does_not_emit_bruteforce_success():
    findings = correlation_findings([
        event(10, "FAILED_LOGIN", 0),
        event(11, "FAILED_LOGIN", 1),
        event(12, "FAILED_LOGIN", 2),
        event(13, "LOGON_SUCCESS", 8),
    ])

    assert "AG-CORR-AUTH-001A" in findings
    assert "AG-CORR-AUTH-001B" not in findings


def test_success_exactly_at_five_minute_boundary_is_correlated():
    findings = correlation_findings([
        event(20, "FAILED_LOGIN", 0),
        event(21, "FAILED_LOGIN", 1),
        event(22, "FAILED_LOGIN", 2),
        event(23, "LOGON_SUCCESS", 7),
    ])

    assert "AG-CORR-AUTH-001A" in findings
    assert "AG-CORR-AUTH-001B" in findings


def test_admin_change_outside_five_minute_window_is_not_privilege_correlation():
    findings = correlation_findings([
        event(30, "LOGON_SUCCESS", 0),
        event(31, "ADMIN_GROUP_ADDED", 6),
    ])

    assert "AG-CORR-PRIV-001A" not in findings


def test_privilege_correlation_never_crosses_host_boundary():
    findings = correlation_findings([
        event(
            40,
            "LOGON_SUCCESS",
            0,
            hostname="HOST-A",
        ),
        event(
            41,
            "ADMIN_GROUP_ADDED",
            1,
            hostname="HOST-B",
        ),
    ])

    assert "AG-CORR-PRIV-001A" not in findings


def test_correlation_finding_ids_are_stable_when_input_order_changes():
    records = [
        event(50, "FAILED_LOGIN", 0),
        event(51, "FAILED_LOGIN", 1),
        event(52, "FAILED_LOGIN", 2),
        event(53, "LOGON_SUCCESS", 3),
        event(54, "ADMIN_GROUP_ADDED", 4),
    ]

    forward = correlation_findings(records)
    reverse = correlation_findings(reversed(records))

    assert {
        key: finding.finding_id
        for key, finding in forward.items()
    } == {
        key: finding.finding_id
        for key, finding in reverse.items()
    }


class ModelWithoutProbability:
    def predict(self, frame):
        return [1]


class BruteForceEncoder:
    def inverse_transform(self, values):
        return ["BRUTE_FORCE" for _ in values]


def test_ml_prediction_without_predict_proba_is_explicit_fallback():
    engine = MLEngine(
        model=ModelWithoutProbability(),
        encoder=BruteForceEncoder(),
        model_name="aegis-threat-classifier",
        model_version="y10-test",
    )

    prediction = engine.predict([
        event(60, "FAILED_LOGIN"),
    ])

    assert prediction.prediction == "BRUTE_FORCE"
    assert prediction.confidence == 0.0
    assert prediction.fallback_reason == "model does not expose predict_proba"


def test_ml_engine_rejects_empty_event_batch():
    engine = MLEngine(
        model=ModelWithoutProbability(),
        encoder=BruteForceEncoder(),
        model_name="aegis-threat-classifier",
        model_version="y10-test",
    )

    with pytest.raises(ValueError, match="at least one event"):
        engine.predict([])


def test_registry_detects_encoder_artifact_tampering(tmp_path):
    rows = []
    labels = []

    for index in range(6):
        row = {column: 0 for column in FEATURE_COLUMNS}

        if index % 2:
            row["FAILED_LOGIN"] = 4
            row["TOTAL_EVENTS"] = 4
            labels.append("BRUTE_FORCE")
        else:
            row["LOGON_SUCCESS"] = 2
            row["TOTAL_EVENTS"] = 2
            labels.append("NORMAL")

        rows.append(row)

    features = pd.DataFrame(rows, columns=FEATURE_COLUMNS)

    encoder = LabelEncoder()
    encoded = encoder.fit_transform(labels)

    model = RandomForestClassifier(
        n_estimators=5,
        random_state=42,
    ).fit(features, encoded)

    evaluation = EvaluationMetrics(
        accuracy=1.0,
        macro_f1=1.0,
        weighted_f1=1.0,
        sample_count=6,
        labels=("BRUTE_FORCE", "NORMAL"),
        confusion_matrix=((3, 0), (0, 3)),
    )

    registry = ModelRegistry(tmp_path)

    registry.register_candidate(
        model=model,
        encoder=encoder,
        model_name="aegis-threat-classifier",
        model_version="y10-candidate.1",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        training_data_fingerprint=fingerprint_training_data(
            features,
            labels,
        ),
        evaluation=evaluation,
        trained_at="2026-09-23T00:00:00Z",
    )

    encoder_path = (
        tmp_path
        / "aegis-threat-classifier"
        / "y10-candidate.1"
        / "encoder.joblib"
    )

    with encoder_path.open("ab") as handle:
        handle.write(b"tampered")

    with pytest.raises(
        ArtifactIntegrityError,
        match="encoder artifact SHA-256 mismatch",
    ):
        registry.load(
            "aegis-threat-classifier",
            "y10-candidate.1",
        )
