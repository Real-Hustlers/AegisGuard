import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from backend.analyzer.intelligence.ml_runtime import (
    GovernedMLRuntimeStatus,
    load_governed_ml_runtime,
)
from backend.analyzer.ml import (
    EvaluationMetrics,
    FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
    ModelRegistry,
    assess_candidate,
    fingerprint_training_data,
)


MODEL_NAME = "aegis-threat-classifier"
MODEL_VERSION = "1.0.0-candidate.1"


def metric():
    return EvaluationMetrics(
        accuracy=1.0,
        macro_f1=1.0,
        weighted_f1=1.0,
        sample_count=6,
        labels=("BRUTE_FORCE", "NORMAL"),
        confusion_matrix=((3, 0), (0, 3)),
    )


def register_candidate(registry):
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

    features = pd.DataFrame(
        rows,
        columns=FEATURE_COLUMNS,
    )

    encoder = LabelEncoder()
    encoded = encoder.fit_transform(labels)

    model = RandomForestClassifier(
        n_estimators=5,
        random_state=42,
    ).fit(features, encoded)

    registry.register_candidate(
        model=model,
        encoder=encoder,
        model_name=MODEL_NAME,
        model_version=MODEL_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        training_data_fingerprint=fingerprint_training_data(
            features,
            labels,
        ),
        evaluation=metric(),
        trained_at="2026-09-23T00:00:00Z",
    )


def promote(registry):
    register_candidate(registry)

    registry.promote(
        MODEL_NAME,
        MODEL_VERSION,
        approved_by="security-lead",
        approved_at="2026-09-23T00:10:00Z",
        assessment=assess_candidate(metric()),
    )


def test_runtime_is_unavailable_when_no_promoted_model_exists(
    tmp_path,
):
    registry = ModelRegistry(tmp_path)

    runtime = load_governed_ml_runtime(
        registry,
        model_name=MODEL_NAME,
    )

    assert runtime.status is GovernedMLRuntimeStatus.UNAVAILABLE
    assert runtime.available is False
    assert runtime.engine is None
    assert runtime.model_name == MODEL_NAME
    assert runtime.model_version is None
    assert runtime.feature_schema_version is None
    assert runtime.reason == "no promoted model"


def test_runtime_loads_only_verified_promoted_engine(tmp_path):
    registry = ModelRegistry(tmp_path)

    promote(registry)

    runtime = load_governed_ml_runtime(
        registry,
        model_name=MODEL_NAME,
    )

    assert runtime.status is GovernedMLRuntimeStatus.AVAILABLE
    assert runtime.available is True
    assert runtime.engine is not None
    assert runtime.model_name == MODEL_NAME
    assert runtime.model_version == MODEL_VERSION
    assert runtime.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert runtime.reason is None


def test_runtime_degrades_when_promoted_model_artifact_is_corrupt(
    tmp_path,
):
    registry = ModelRegistry(tmp_path)

    promote(registry)

    model_path = (
        tmp_path
        / MODEL_NAME
        / MODEL_VERSION
        / "model.joblib"
    )

    with model_path.open("ab") as handle:
        handle.write(b"tampered")

    runtime = load_governed_ml_runtime(
        registry,
        model_name=MODEL_NAME,
    )

    assert runtime.status is GovernedMLRuntimeStatus.DEGRADED
    assert runtime.available is False
    assert runtime.engine is None
    assert runtime.model_name == MODEL_NAME
    assert runtime.model_version == MODEL_VERSION
    assert runtime.reason is not None
    assert "SHA-256 mismatch" in runtime.reason


def test_runtime_status_serializes_without_exposing_engine(tmp_path):
    registry = ModelRegistry(tmp_path)

    promote(registry)

    runtime = load_governed_ml_runtime(
        registry,
        model_name=MODEL_NAME,
    )

    payload = runtime.to_dict()

    assert payload == {
        "status": "AVAILABLE",
        "available": True,
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "reason": None,
    }

    assert "engine" not in payload
