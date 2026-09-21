import pytest

from backend.analyzer.detection import DetectionType, Severity
from backend.analyzer.detection.adapters import (
    canonical_event_from_legacy,
    normalize_severity,
    rule_finding_from_legacy_classification,
)


def test_canonical_event_adapter_uses_existing_log_id_and_preserves_extra_fields():
    record = {
        "log_id": "LOG-000123",
        "timestamp": "2026-09-21T04:00:00Z",
        "event_type": "FAILED_LOGIN",
        "severity": "Information",
        "hostname": "WIN-LAB-01",
        "source_ip": "10.0.0.5",
        "raw_log": "An account failed to log on",
        "windows_event_id": 4625,
    }

    event = canonical_event_from_legacy(record)

    assert event.event_id == "LOG-000123"
    assert event.severity == "INFO"
    assert event.raw_event == "An account failed to log on"
    assert event.attributes["windows_event_id"] == 4625


def test_canonical_event_adapter_rejects_records_without_identity():
    with pytest.raises(ValueError, match="requires event_id, log_id, or record_id"):
        canonical_event_from_legacy({
            "timestamp": "2026-09-21T04:00:00Z",
            "event_type": "FAILED_LOGIN",
        })


def test_severity_normalization_is_conservative_for_unrecognized_values():
    assert normalize_severity("critical") is Severity.CRITICAL
    assert normalize_severity("Information") is Severity.INFO
    assert normalize_severity("vendor-custom") is Severity.INFO


def test_legacy_deterministic_prediction_becomes_rule_not_ml():
    finding = rule_finding_from_legacy_classification(
        {
            "log_id": "LOG-000124",
            "timestamp": "2026-09-21T04:01:00Z",
            "event_type": "FAILED_LOGIN",
            "severity": "Information",
            "threat_level": "HIGH",
            "ml_prediction": "BRUTE_FORCE",
            "threat_score": 80,
            "raw_log": "An account failed to log on",
        },
        finding_id="FND-000124",
        rule_id="AG-RULE-AUTH-001",
        name="Windows failed login",
        reason="Legacy deterministic FAILED_LOGIN override",
    )

    assert finding.detection_type is DetectionType.RULE
    assert finding.severity is Severity.HIGH
    assert finding.model_version is None
    assert finding.prediction_source == "rule:AG-RULE-AUTH-001"
    assert finding.evidence[0]["legacy_prediction"] == "BRUTE_FORCE"
