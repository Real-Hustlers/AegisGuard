import json

import pytest

from backend.analyzer.detection.contracts import CanonicalEvent
from backend.analyzer.ml.engine import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION
from backend.analyzer.ml.history import (
    HistoricalDisposition,
    HistoricalObservation,
    build_historical_dataset,
    known_benign_observation,
    observation_from_incident_review,
    train_historical_candidate,
)
from backend.platform.contracts import IncidentLifecycleStatus


def event(index, event_type, *, raw_event=None, **kwargs):
    return CanonicalEvent(
        event_id=f"EVT-{index:04d}",
        timestamp=f"2026-09-22T08:{index % 60:02d}:00Z",
        event_type=event_type,
        severity=kwargs.pop("severity", "LOW"),
        hostname=kwargs.pop("hostname", "WIN-HISTORY"),
        user=kwargs.pop("user", "alice"),
        source_ip=kwargs.pop("source_ip", "10.0.0.5"),
        raw_event=raw_event,
        attributes=kwargs.pop("attributes", {}),
        **kwargs,
    )


def reviewed_tp(index, label="BRUTE_FORCE"):
    return HistoricalObservation(
        observation_id=f"OBS-TP-{index:02d}",
        incident_id=f"INC-{index:02d}",
        events=(event(index, "FAILED_LOGIN", severity="HIGH"),),
        disposition=HistoricalDisposition.TRUE_POSITIVE,
        reviewed_by="analyst-1",
        reviewed_at="2026-09-22T09:00:00Z",
        threat_label=label,
    )


def reviewed_benign(index):
    return known_benign_observation(
        observation_id=f"OBS-BENIGN-{index:02d}",
        events=(event(100 + index, "LOGON_SUCCESS"),),
        reviewed_by="analyst-2",
        reviewed_at="2026-09-22T09:05:00Z",
    )


def test_true_positive_requires_explicit_threat_label():
    with pytest.raises(ValueError, match="explicit threat_label"):
        HistoricalObservation(
            observation_id="OBS-1",
            events=(event(1, "FAILED_LOGIN"),),
            disposition=HistoricalDisposition.TRUE_POSITIVE,
            reviewed_by="analyst",
            reviewed_at="2026-09-22T09:00:00Z",
        )


def test_true_positive_rejects_normal_or_unknown_as_threat_class():
    for label in ("NORMAL", "UNKNOWN"):
        with pytest.raises(ValueError, match="confirmed threat class"):
            HistoricalObservation(
                observation_id=f"OBS-{label}",
                events=(event(2, "FAILED_LOGIN"),),
                disposition=HistoricalDisposition.TRUE_POSITIVE,
                reviewed_by="analyst",
                reviewed_at="2026-09-22T09:00:00Z",
                threat_label=label,
            )


def test_false_positive_becomes_normal_and_rejects_attack_label():
    observation = HistoricalObservation(
        observation_id="OBS-FP",
        events=(event(3, "DEFENDER_ALERT"),),
        disposition=HistoricalDisposition.FALSE_POSITIVE,
        reviewed_by="analyst",
        reviewed_at="2026-09-22T09:00:00Z",
    )
    assert observation.training_label == "NORMAL"
    with pytest.raises(ValueError, match="may only use NORMAL"):
        HistoricalObservation(
            observation_id="OBS-FP-BAD",
            events=(event(4, "DEFENDER_ALERT"),),
            disposition=HistoricalDisposition.FALSE_POSITIVE,
            reviewed_by="analyst",
            reviewed_at="2026-09-22T09:00:00Z",
            threat_label="MALWARE",
        )


def test_known_benign_helper_creates_explicit_normal_review():
    observation = reviewed_benign(1)
    assert observation.disposition is HistoricalDisposition.KNOWN_BENIGN
    assert observation.training_label == "NORMAL"


def test_incident_confirmed_review_requires_and_preserves_explicit_label():
    observation = observation_from_incident_review(
        observation_id="OBS-INC-1",
        incident_id="INC-1",
        lifecycle_status=IncidentLifecycleStatus.CONFIRMED,
        events=(event(5, "FAILED_LOGIN"),),
        reviewed_by="analyst",
        reviewed_at="2026-09-22T09:00:00Z",
        confirmed_label="brute_force",
    )
    assert observation.training_label == "BRUTE_FORCE"
    assert observation.incident_id == "INC-1"


def test_incident_false_positive_review_maps_to_normal():
    observation = observation_from_incident_review(
        observation_id="OBS-INC-2",
        incident_id="INC-2",
        lifecycle_status="FALSE_POSITIVE",
        events=(event(6, "DEFENDER_ALERT"),),
        reviewed_by="analyst",
        reviewed_at="2026-09-22T09:00:00Z",
    )
    assert observation.training_label == "NORMAL"


def test_non_truth_incident_statuses_are_not_training_labels():
    for status in (
        IncidentLifecycleStatus.OPEN,
        IncidentLifecycleStatus.INVESTIGATING,
        IncidentLifecycleStatus.CONTAINMENT,
        IncidentLifecycleStatus.RESOLVED,
        IncidentLifecycleStatus.CLOSED,
    ):
        with pytest.raises(ValueError, match="requires CONFIRMED or FALSE_POSITIVE"):
            observation_from_incident_review(
                observation_id=f"OBS-{status.value}",
                incident_id=f"INC-{status.value}",
                lifecycle_status=status,
                events=(event(7, "FAILED_LOGIN"),),
                reviewed_by="analyst",
                reviewed_at="2026-09-22T09:00:00Z",
                confirmed_label="BRUTE_FORCE",
            )


def test_review_identity_and_timestamp_are_required():
    with pytest.raises(ValueError, match="reviewed_by"):
        HistoricalObservation(
            observation_id="OBS-NO-REVIEWER",
            events=(event(8, "LOGON_SUCCESS"),),
            disposition=HistoricalDisposition.KNOWN_BENIGN,
            reviewed_by="",
            reviewed_at="2026-09-22T09:00:00Z",
        )


def test_dataset_uses_exact_y2_feature_schema_and_review_labels():
    dataset = build_historical_dataset([reviewed_tp(10), reviewed_benign(10)])
    assert tuple(dataset.features.columns) == FEATURE_COLUMNS
    assert dataset.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert dataset.sample_count == 2
    assert dataset.class_counts == {"BRUTE_FORCE": 1, "NORMAL": 1}
    assert tuple(dataset.to_training_frame().columns) == FEATURE_COLUMNS + ("LABEL",)


def test_dataset_order_and_fingerprints_are_deterministic():
    first = reviewed_tp(11)
    second = reviewed_benign(11)
    a = build_historical_dataset([first, second])
    b = build_historical_dataset([second, first])
    assert a.observation_ids == b.observation_ids
    assert a.training_data_fingerprint == b.training_data_fingerprint
    assert a.review_provenance_fingerprint == b.review_provenance_fingerprint


def test_dataset_rejects_duplicate_observation_ids():
    first = reviewed_tp(12)
    duplicate = HistoricalObservation(
        observation_id=first.observation_id,
        events=(event(212, "LOGON_SUCCESS"),),
        disposition=HistoricalDisposition.KNOWN_BENIGN,
        reviewed_by="analyst",
        reviewed_at="2026-09-22T09:00:00Z",
    )
    with pytest.raises(ValueError, match="observation_id values must be unique"):
        build_historical_dataset([first, duplicate])


def test_dataset_rejects_event_reuse_across_reviewed_observations():
    shared = event(13, "FAILED_LOGIN")
    first = HistoricalObservation(
        observation_id="OBS-A",
        events=(shared,),
        disposition=HistoricalDisposition.TRUE_POSITIVE,
        reviewed_by="analyst",
        reviewed_at="2026-09-22T09:00:00Z",
        threat_label="BRUTE_FORCE",
    )
    second = HistoricalObservation(
        observation_id="OBS-B",
        events=(shared,),
        disposition=HistoricalDisposition.FALSE_POSITIVE,
        reviewed_by="analyst-2",
        reviewed_at="2026-09-22T09:10:00Z",
    )
    with pytest.raises(ValueError, match="appears in multiple reviewed observations"):
        build_historical_dataset([first, second])


def test_manifest_keeps_lineage_but_excludes_raw_event_content():
    secret = "raw-sensitive-event-content"
    observation = HistoricalObservation(
        observation_id="OBS-RAW",
        incident_id="INC-RAW",
        events=(event(14, "FAILED_LOGIN", raw_event=secret),),
        disposition=HistoricalDisposition.TRUE_POSITIVE,
        reviewed_by="analyst",
        reviewed_at="2026-09-22T09:00:00Z",
        threat_label="BRUTE_FORCE",
    )
    manifest = build_historical_dataset([observation]).manifest()
    serialized = json.dumps(manifest)
    assert secret not in serialized
    assert "EVT-0014" in serialized
    assert "INC-RAW" in serialized
    assert len(manifest["review_provenance_fingerprint"]) == 64


def test_model_prediction_metadata_is_not_used_as_training_truth():
    benign = HistoricalObservation(
        observation_id="OBS-PREDICTION-IGNORED",
        events=(
            event(
                15,
                "LOGON_SUCCESS",
                attributes={"ml_prediction": "MALWARE", "ml_confidence": 0.99},
            ),
        ),
        disposition=HistoricalDisposition.FALSE_POSITIVE,
        reviewed_by="analyst",
        reviewed_at="2026-09-22T09:00:00Z",
    )
    dataset = build_historical_dataset([benign])
    assert dataset.labels == ("NORMAL",)


def test_historical_training_feeds_y3_candidate_without_registry_or_promotion():
    observations = []
    for index in range(10):
        observations.append(reviewed_tp(20 + index))
        observations.append(reviewed_benign(20 + index))
    run = train_historical_candidate(observations, n_estimators=10)
    assert run.candidate.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert run.candidate.training_data_fingerprint == run.dataset.training_data_fingerprint
    assert run.candidate.training_sample_count + run.candidate.validation_sample_count == 20
    assert set(run.candidate.encoder.classes_) == {"BRUTE_FORCE", "NORMAL"}


def test_historical_training_keeps_y3_minimum_class_review_gate():
    observations = [reviewed_tp(50), reviewed_tp(51), reviewed_benign(50)]
    with pytest.raises(ValueError, match="every class requires at least two samples"):
        train_historical_candidate(observations, n_estimators=10)
