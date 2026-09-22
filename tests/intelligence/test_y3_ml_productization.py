import json
from pathlib import Path

import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from backend.analyzer.ml import (
    ArtifactIntegrityError,
    EvaluationMetrics,
    FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
    ModelCompatibilityError,
    ModelRegistry,
    ModelRegistryError,
    ModelStage,
    PromotionPolicy,
    assess_candidate,
    fingerprint_training_data,
    train_candidate,
)


def feature_frame(rows=20):
    data = []
    labels = []
    for index in range(rows):
        malicious = index % 2 == 1
        row = {column: 0 for column in FEATURE_COLUMNS}
        if malicious:
            row["FAILED_LOGIN"] = 5
            row["TOTAL_EVENTS"] = 5
            row["HIGH_EVENTS"] = 5
            labels.append("BRUTE_FORCE")
        else:
            row["LOGON_SUCCESS"] = 2
            row["TOTAL_EVENTS"] = 2
            labels.append("NORMAL")
        data.append(row)
    return pd.DataFrame(data, columns=FEATURE_COLUMNS), labels


def metric(accuracy, macro_f1):
    return EvaluationMetrics(
        accuracy=accuracy,
        macro_f1=macro_f1,
        weighted_f1=macro_f1,
        sample_count=20,
        labels=("BRUTE_FORCE", "NORMAL"),
        confusion_matrix=((10, 0), (0, 10)),
    )


def trained_components():
    features, labels = feature_frame()
    encoder = LabelEncoder()
    encoded = encoder.fit_transform(labels)
    model = RandomForestClassifier(n_estimators=10, random_state=42).fit(features, encoded)
    return features, labels, model, encoder


def register(registry, version="0.2.0-candidate.1"):
    features, labels, model, encoder = trained_components()
    return registry.register_candidate(
        model=model,
        encoder=encoder,
        model_name="aegis-threat-classifier",
        model_version=version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        training_data_fingerprint=fingerprint_training_data(features, labels),
        evaluation=metric(1.0, 1.0),
        trained_at="2026-09-21T07:00:00Z",
    )


def test_training_requires_exact_feature_schema_order():
    features, labels = feature_frame()
    bad = features[list(reversed(FEATURE_COLUMNS))]
    with pytest.raises(ValueError, match="exactly match FEATURE_COLUMNS"):
        train_candidate(bad, labels)


def test_training_rejects_classes_without_enough_validation_samples():
    features, labels = feature_frame(4)
    labels[-1] = "RARE"
    with pytest.raises(ValueError, match="every class requires at least two samples"):
        train_candidate(features, labels)


def test_training_rejects_split_too_small_for_all_classes():
    features, labels = feature_frame(4)
    with pytest.raises(ValueError, match="too small for a stratified"):
        train_candidate(features, labels, validation_fraction=0.20)


def test_train_candidate_is_offline_and_returns_evaluation():
    features, labels = feature_frame()
    candidate = train_candidate(features, labels, n_estimators=10)
    assert candidate.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert candidate.training_sample_count + candidate.validation_sample_count == len(features)
    assert 0.0 <= candidate.evaluation.accuracy <= 1.0
    assert len(candidate.training_data_fingerprint) == 64


def test_candidate_assessment_requires_absolute_quality():
    assessment = assess_candidate(
        metric(0.60, 0.55),
        policy=PromotionPolicy(min_accuracy=0.70, min_macro_f1=0.60),
    )
    assert not assessment.eligible_for_approval
    assert len(assessment.reasons) == 2


def test_candidate_assessment_blocks_regression_against_current():
    assessment = assess_candidate(
        metric(0.91, 0.89),
        current=metric(0.96, 0.95),
        policy=PromotionPolicy(max_accuracy_drop=0.02, max_macro_f1_drop=0.02),
    )
    assert not assessment.eligible_for_approval
    assert assessment.accuracy_delta == pytest.approx(-0.05)


def test_candidate_assessment_can_become_eligible_but_does_not_promote():
    assessment = assess_candidate(metric(0.95, 0.94), current=metric(0.94, 0.93))
    assert assessment.eligible_for_approval
    assert assessment.reasons == ()


def test_registry_registration_creates_candidate_not_active_model(tmp_path):
    registry = ModelRegistry(tmp_path)
    metadata = register(registry)
    assert metadata.stage is ModelStage.CANDIDATE
    assert registry.get_promoted_metadata("aegis-threat-classifier") is None
    assert len(metadata.model_sha256) == 64
    assert len(metadata.encoder_sha256) == 64


def test_registry_rejects_duplicate_version(tmp_path):
    registry = ModelRegistry(tmp_path)
    register(registry)
    with pytest.raises(ModelRegistryError, match="already exists"):
        register(registry)


def test_promotion_requires_explicit_approver(tmp_path):
    registry = ModelRegistry(tmp_path)
    register(registry)
    assessment = assess_candidate(metric(1.0, 1.0))
    with pytest.raises(ValueError, match="approved_by"):
        registry.promote(
            "aegis-threat-classifier",
            "0.2.0-candidate.1",
            approved_by="",
            assessment=assessment,
        )


def test_promotion_rejects_assessment_for_different_candidate_metrics(tmp_path):
    registry = ModelRegistry(tmp_path)
    register(registry)
    with pytest.raises(ModelRegistryError, match="does not match the registered candidate"):
        registry.promote(
            "aegis-threat-classifier",
            "0.2.0-candidate.1",
            approved_by="security-lead",
            assessment=assess_candidate(metric(0.95, 0.95)),
        )


def test_promotion_rejects_ineligible_candidate(tmp_path):
    registry = ModelRegistry(tmp_path)
    register(registry)
    with pytest.raises(ModelRegistryError, match="not eligible"):
        registry.promote(
            "aegis-threat-classifier",
            "0.2.0-candidate.1",
            approved_by="analyst@example",
            assessment=assess_candidate(metric(0.40, 0.40)),
        )


def test_explicit_promotion_sets_active_version_and_engine_identity(tmp_path):
    registry = ModelRegistry(tmp_path)
    register(registry)
    promoted = registry.promote(
        "aegis-threat-classifier",
        "0.2.0-candidate.1",
        approved_by="security-lead",
        approved_at="2026-09-21T07:30:00Z",
        assessment=assess_candidate(metric(1.0, 1.0)),
    )
    assert promoted.stage is ModelStage.PROMOTED
    assert promoted.approved_by == "security-lead"
    active = registry.get_promoted_metadata("aegis-threat-classifier")
    assert active is not None
    assert active.model_version == "0.2.0-candidate.1"
    engine = registry.load_promoted_engine("aegis-threat-classifier")
    assert engine.model_version == "0.2.0-candidate.1"


def test_registry_detects_artifact_tampering_before_unpickle(tmp_path):
    registry = ModelRegistry(tmp_path)
    register(registry)
    model_path = (
        Path(tmp_path)
        / "aegis-threat-classifier"
        / "0.2.0-candidate.1"
        / "model.joblib"
    )
    with open(model_path, "ab") as handle:
        handle.write(b"tampered")
    with pytest.raises(ArtifactIntegrityError, match="SHA-256 mismatch"):
        registry.load("aegis-threat-classifier", "0.2.0-candidate.1")


def test_registry_rejects_feature_schema_mismatch(tmp_path):
    registry = ModelRegistry(tmp_path)
    register(registry)
    with pytest.raises(ModelCompatibilityError, match="feature schema mismatch"):
        registry.load(
            "aegis-threat-classifier",
            "0.2.0-candidate.1",
            expected_feature_schema_version="future-schema-v2",
        )


def test_registry_retires_previous_active_model_on_new_promotion(tmp_path):
    registry = ModelRegistry(tmp_path)
    register(registry, "0.2.0-candidate.1")
    eligible = assess_candidate(metric(1.0, 1.0))
    registry.promote(
        "aegis-threat-classifier",
        "0.2.0-candidate.1",
        approved_by="security-lead",
        assessment=eligible,
    )
    register(registry, "0.2.0-candidate.2")
    compared = assess_candidate(metric(1.0, 1.0), current=metric(1.0, 1.0))
    registry.promote(
        "aegis-threat-classifier",
        "0.2.0-candidate.2",
        approved_by="security-lead",
        assessment=compared,
    )
    old = registry.read_metadata("aegis-threat-classifier", "0.2.0-candidate.1")
    new = registry.get_promoted_metadata("aegis-threat-classifier")
    assert old.stage is ModelStage.RETIRED
    assert new is not None and new.model_version == "0.2.0-candidate.2"


def test_registry_rejects_sklearn_runtime_mismatch(tmp_path):
    registry = ModelRegistry(tmp_path)
    register(registry)
    metadata_path = (
        Path(tmp_path)
        / "aegis-threat-classifier"
        / "0.2.0-candidate.1"
        / "metadata.json"
    )
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    payload["sklearn_version"] = "0.0.0-incompatible"
    metadata_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ModelCompatibilityError, match="scikit-learn version mismatch"):
        registry.load("aegis-threat-classifier", "0.2.0-candidate.1")
