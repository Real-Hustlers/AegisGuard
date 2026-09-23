import json

import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from backend.analyzer.ml import (
    EvaluationMetrics,
    FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
    ModelRegistry,
    ModelRegistryError,
    ModelStage,
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


def trained_components():
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

    return features, labels, model, encoder


def register_candidate(registry):
    features, labels, model, encoder = trained_components()

    return registry.register_candidate(
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


def test_registry_loads_explicitly_promoted_engine(tmp_path):
    registry = ModelRegistry(tmp_path)

    register_candidate(registry)

    promoted = registry.promote(
        MODEL_NAME,
        MODEL_VERSION,
        approved_by="security-lead",
        approved_at="2026-09-23T00:10:00Z",
        assessment=assess_candidate(metric()),
    )

    assert promoted.stage is ModelStage.PROMOTED

    engine = registry.load_promoted_engine(
        MODEL_NAME
    )

    assert engine.model_name == MODEL_NAME
    assert engine.model_version == MODEL_VERSION
    assert (
        engine.feature_schema_version
        == FEATURE_SCHEMA_VERSION
    )


def test_registry_refuses_active_pointer_to_candidate(tmp_path):
    registry = ModelRegistry(tmp_path)

    candidate = register_candidate(registry)

    assert candidate.stage is ModelStage.CANDIDATE

    model_dir = (
        tmp_path
        / MODEL_NAME
    )

    active_path = model_dir / "active.json"

    active_path.write_text(
        json.dumps({
            "model_name": MODEL_NAME,
            "model_version": MODEL_VERSION,
            "approved_by": "forged-pointer",
            "approved_at": "2026-09-23T00:10:00Z",
        }),
        encoding="utf-8",
    )

    with pytest.raises(
        ModelRegistryError,
        match="PROMOTED",
    ):
        registry.load_promoted_engine(
            MODEL_NAME
        )


def test_registry_without_active_model_is_explicitly_unavailable(
    tmp_path,
):
    registry = ModelRegistry(tmp_path)

    register_candidate(registry)

    with pytest.raises(
        ModelRegistryError,
        match="no promoted model",
    ):
        registry.load_promoted_engine(
            MODEL_NAME
        )
