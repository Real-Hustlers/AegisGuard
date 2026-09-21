from dataclasses import FrozenInstanceError

import pytest

from backend.analyzer.detection import (
    CONTRACT_VERSION,
    CanonicalEvent,
    DetectionFinding,
    DetectionType,
    IncidentCandidate,
    MLPrediction,
    MITREMapping,
    Severity,
)


def test_canonical_event_preserves_source_specific_attributes_and_raw_event():
    event = CanonicalEvent(
        event_id="LOG-000001",
        timestamp="2026-09-21T03:30:00Z",
        event_type="FAILED_LOGIN",
        severity="HIGH",
        hostname="WIN-LAB-01",
        source_ip="10.10.0.5",
        raw_event="original event text",
        attributes={"windows_event_id": 4625, "logon_type": 3},
    )

    payload = event.to_dict()

    assert payload["schema_version"] == CONTRACT_VERSION
    assert payload["raw_event"] == "original event text"
    assert payload["attributes"] == {"windows_event_id": 4625, "logon_type": 3}


def test_detection_type_values_are_explicit_and_stable():
    assert DetectionType.RULE.value == "RULE"
    assert DetectionType.ML.value == "ML"
    assert DetectionType.CORRELATION.value == "CORRELATION"


def test_rule_finding_does_not_masquerade_as_ml():
    finding = DetectionFinding(
        finding_id="FND-000001",
        event_ids=("LOG-000001",),
        detection_type=DetectionType.RULE,
        name="Windows failed login",
        severity=Severity.HIGH,
        confidence=1.0,
        reason="Event type FAILED_LOGIN matched deterministic rule AG-RULE-AUTH-001",
        timestamp="2026-09-21T03:30:00Z",
        prediction_source="rule:AG-RULE-AUTH-001",
        rule_id="AG-RULE-AUTH-001",
    )

    payload = finding.to_dict()

    assert payload["detection_type"] == "RULE"
    assert payload["model_version"] is None
    assert payload["prediction_source"] == "rule:AG-RULE-AUTH-001"


def test_ml_finding_requires_model_version():
    with pytest.raises(ValueError, match="model_version is required"):
        DetectionFinding(
            finding_id="FND-ML-001",
            event_ids=("LOG-000002",),
            detection_type=DetectionType.ML,
            name="ML anomaly",
            severity=Severity.MEDIUM,
            confidence=0.82,
            reason="Model classified the event sequence as anomalous",
            timestamp="2026-09-21T03:31:00Z",
            prediction_source="model:aegis-threat-classifier",
        )


def test_confidence_contract_is_unambiguous_unit_interval():
    with pytest.raises(ValueError, match="between 0.0 and 1.0"):
        DetectionFinding(
            finding_id="FND-000002",
            event_ids=("LOG-000002",),
            detection_type=DetectionType.RULE,
            name="Bad confidence",
            severity=Severity.LOW,
            confidence=96.0,
            reason="Legacy percentage must be converted at the adapter boundary",
            timestamp="2026-09-21T03:31:00Z",
            prediction_source="rule:test",
        )


def test_mitre_mapping_is_structured_and_serializable():
    mapping = MITREMapping(
        technique_id="T1110",
        technique="Brute Force",
        tactic="Credential Access",
    )
    finding = DetectionFinding(
        finding_id="FND-000003",
        event_ids=("LOG-000003",),
        detection_type=DetectionType.CORRELATION,
        name="Repeated failures followed by success",
        severity=Severity.CRITICAL,
        confidence=0.95,
        reason="Three failed logons were followed by a successful logon from the same source",
        timestamp="2026-09-21T03:35:00Z",
        prediction_source="correlation:AG-CORR-AUTH-001",
        correlation_id="AG-CORR-AUTH-001",
        mitre=(mapping,),
    )

    assert finding.to_dict()["mitre"] == [
        {
            "technique_id": "T1110",
            "technique": "Brute Force",
            "tactic": "Credential Access",
        }
    ]


def test_ml_prediction_carries_model_and_feature_versions():
    prediction = MLPrediction(
        prediction="BRUTE_FORCE",
        confidence=0.91,
        model_name="aegis-threat-classifier",
        model_version="0.1.0-candidate.1",
        feature_schema_version="1.0",
        prediction_source="model:aegis-threat-classifier",
        event_ids=("LOG-000010", "LOG-000011"),
        timestamp="2026-09-21T03:40:00Z",
    )

    payload = prediction.to_dict()

    assert payload["model_version"] == "0.1.0-candidate.1"
    assert payload["feature_schema_version"] == "1.0"
    assert payload["confidence"] == 0.91


def test_incident_candidate_links_findings_and_events_without_owning_lifecycle_state():
    candidate = IncidentCandidate(
        candidate_id="CAN-000001",
        finding_ids=("FND-000003",),
        event_ids=("LOG-000003", "LOG-000004"),
        name="Potential account compromise",
        severity=Severity.CRITICAL,
        confidence=0.95,
        reason="Correlated authentication sequence requires incident review",
        timestamp="2026-09-21T03:35:00Z",
        related_entities={
            "hosts": ("WIN-LAB-01",),
            "users": ("alice",),
            "source_ips": ("10.10.0.5",),
        },
    )

    payload = candidate.to_dict()

    assert payload["finding_ids"] == ["FND-000003"]
    assert payload["event_ids"] == ["LOG-000003", "LOG-000004"]
    assert "status" not in payload
    assert "response" not in payload


def test_contracts_are_frozen_at_top_level():
    finding = DetectionFinding(
        finding_id="FND-000004",
        event_ids=("LOG-000020",),
        detection_type=DetectionType.RULE,
        name="Immutable finding",
        severity=Severity.LOW,
        confidence=1.0,
        reason="Contract objects should not be reassigned after construction",
        timestamp="2026-09-21T03:45:00Z",
        prediction_source="rule:test",
    )

    with pytest.raises(FrozenInstanceError):
        finding.name = "changed"
