import json

import pytest

from backend.analyzer.intelligence.lab_validation import (
    LAB_VALIDATION_VERSION,
    SCENARIOS,
    main,
    normalize_lab_records,
    validate_lab_payload,
    validate_lab_records,
)


def event(
    n,
    event_type,
    minute,
    *,
    hostname="Y9-LAB",
    user="alice",
    source_ip="10.0.0.5",
    process="powershell.exe",
):
    return {
        "record_id": n,
        "hostname": hostname,
        "timestamp": f"2026-09-22T10:{minute:02d}:00Z",
        "event_type": event_type,
        "user": user,
        "source_ip": source_ip,
        "destination_ip": "10.0.0.10",
        "process": process,
        "severity": "HIGH",
        "raw_log": f"lab event {n}: {event_type}",
    }


def credential_to_privilege():
    return [
        event(1, "FAILED_LOGIN", 0),
        event(2, "FAILED_LOGIN", 1),
        event(3, "FAILED_LOGIN", 2),
        event(4, "LOGON_SUCCESS", 3),
        event(5, "ADMIN_GROUP_ADDED", 4),
    ]


def discovery_to_persistence():
    return [
        event(1, "LOCAL_GROUP_ENUMERATION", 0),
        event(2, "PROCESS_CREATED", 1, process="cmd.exe"),
        event(3, "NETWORK_CONNECTION", 2),
        event(4, "USER_CREATED", 3),
        event(5, "PASSWORD_CHANGED", 4),
        event(6, "LOGON_SUCCESS", 5),
    ]


def test_validation_version_and_scenario_catalog_are_explicit():
    assert LAB_VALIDATION_VERSION == "isolated-lab-validation-v1"
    assert set(SCENARIOS) == {
        "credential-to-privilege",
        "discovery-to-persistence",
    }


def test_credential_to_privilege_scenario_passes_real_pipeline():
    report = validate_lab_records(
        credential_to_privilege(),
        "credential-to-privilege",
    )

    assert report.passed is True
    assert "AG-RULE-AUTH-001" in report.observed_rule_ids
    assert "AG-CORR-AUTH-001B" in report.observed_correlation_ids
    assert "AG-CORR-PRIV-001A" in report.observed_correlation_ids
    assert "T1110" in report.observed_technique_ids
    assert "T1098.007" in report.observed_technique_ids
    assert "CREDENTIAL_ACCESS" in report.observed_attack_stages
    assert "PRIVILEGE_ESCALATION" in report.observed_attack_stages
    assert report.attack_story_count >= 1


def test_discovery_to_persistence_scenario_passes_real_pipeline():
    report = validate_lab_records(
        discovery_to_persistence(),
        "discovery-to-persistence",
    )

    assert report.passed is True
    assert "AG-CORR-DISC-001" in report.observed_correlation_ids
    assert "AG-CORR-PERSIST-001" in report.observed_correlation_ids
    assert "T1069.001" in report.observed_technique_ids
    assert "T1136" in report.observed_technique_ids
    assert "DISCOVERY" in report.observed_attack_stages
    assert "PERSISTENCE" in report.observed_attack_stages


def test_missing_privilege_event_fails_with_specific_evidence_gaps():
    report = validate_lab_records(
        credential_to_privilege()[:-1],
        "credential-to-privilege",
    )

    assert report.passed is False
    assert "ADMIN_GROUP_ADDED" in report.missing_event_types
    assert "AG-CORR-PRIV-001A" in report.missing_correlation_ids
    assert "T1098.007" in report.missing_technique_ids
    assert "PRIVILEGE_ESCALATION" in report.missing_attack_stages


def test_collector_style_payload_is_accepted_and_log_ids_are_synthesized():
    normalized = normalize_lab_records({"logs": credential_to_privilege()})

    assert len(normalized) == 5
    assert normalized[0]["log_id"] == "lab:y9-lab:1"
    assert normalized[0]["event_type"] == "FAILED_LOGIN"


def test_validation_is_read_only_and_never_executes_response_actions():
    report = validate_lab_records(
        credential_to_privilege(),
        "credential-to-privilege",
    )

    assert report.governance["read_only"] is True
    assert report.governance["writes_database"] is False
    assert report.governance["executes_response_actions"] is False


def test_unknown_scenario_is_rejected():
    with pytest.raises(ValueError, match="unknown lab scenario"):
        validate_lab_records([], "not-a-scenario")


def test_invalid_payload_is_rejected():
    with pytest.raises(ValueError, match="logs list"):
        normalize_lab_records({"logs": "not-a-list"})


def test_cli_writes_json_report_and_returns_success(tmp_path, capsys):
    input_path = tmp_path / "capture.json"
    output_path = tmp_path / "report.json"
    input_path.write_text(
        json.dumps({"logs": credential_to_privilege()}),
        encoding="utf-8",
    )

    code = main([
        "--scenario",
        "credential-to-privilege",
        "--input",
        str(input_path),
        "--output",
        str(output_path),
    ])

    assert code == 0
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["passed"] is True
    assert payload["scenario_id"] == "credential-to-privilege"
    assert '"passed": true' in capsys.readouterr().out.lower()


def test_cli_returns_nonzero_when_expected_detection_is_missing(tmp_path):
    input_path = tmp_path / "capture.json"
    input_path.write_text(
        json.dumps(credential_to_privilege()[:-1]),
        encoding="utf-8",
    )

    code = main([
        "--scenario",
        "credential-to-privilege",
        "--input",
        str(input_path),
    ])

    assert code == 1
