import json

import pytest

from backend.analyzer.intelligence.live_evidence import (
    INTELLIGENCE_EVENT_LIMIT,
    LIVE_EVIDENCE_VERSION,
    finish_capture,
    normalize_analyzer_url,
    response_safety,
    start_capture,
    verify_live_snapshot,
)


SAFE_SETTINGS = {
    "simulation_mode": True,
    "soar_mode": "MANUAL",
    "soar_dry_run": True,
    "auto_response_enabled": True,
}


def api_event(
    n,
    event_type,
    minute,
    *,
    hostname="Y9-LIVE",
    user="alice",
    source_ip="10.0.0.5",
):
    return {
        "id": f"windows:y9-live:{n}",
        "record_id": n,
        "timestamp": f"2026-09-22T10:{minute:02d}:00Z",
        "hostname": hostname,
        "event_type": event_type,
        "user": user,
        "ip": source_ip,
        "severity": "HIGH",
        "event": f"Windows {event_type}",
        "ml_prediction": "BRUTE_FORCE" if event_type == "FAILED_LOGIN" else "NORMAL",
        "threat_level": "HIGH",
        "threat_score": 80,
        "threat_category": "Test",
    }


def credential_events():
    return [
        api_event(1, "FAILED_LOGIN", 0),
        api_event(2, "FAILED_LOGIN", 1),
        api_event(3, "FAILED_LOGIN", 2),
        api_event(4, "LOGON_SUCCESS", 3),
        api_event(5, "ADMIN_GROUP_ADDED", 4),
    ]


def snapshot_for_credential_host(hostname="Y9-LIVE"):
    evidence = [{"hostname": hostname, "source_ip": "10.0.0.5", "user": "alice"}]
    return {
        "scope": {
            "events_analyzed": 5,
            "total_events": 5,
            "truncated": False,
        },
        "findings": {
            "rule": [
                {
                    "rule_id": "AG-RULE-AUTH-001",
                    "evidence": evidence,
                    "mitre": [
                        {
                            "technique_id": "T1110",
                            "technique": "Brute Force",
                            "tactic": "Credential Access",
                        }
                    ],
                }
            ],
            "correlation": [
                {
                    "correlation_id": "AG-CORR-AUTH-001A",
                    "evidence": evidence,
                    "mitre": [
                        {
                            "technique_id": "T1110",
                            "technique": "Brute Force",
                            "tactic": "Credential Access",
                        }
                    ],
                },
                {
                    "correlation_id": "AG-CORR-AUTH-001B",
                    "evidence": evidence,
                    "mitre": [
                        {
                            "technique_id": "T1110",
                            "technique": "Brute Force",
                            "tactic": "Credential Access",
                        }
                    ],
                },
                {
                    "correlation_id": "AG-CORR-PRIV-001A",
                    "evidence": evidence,
                    "mitre": [
                        {
                            "technique_id": "T1098.007",
                            "technique": "Account Manipulation",
                            "tactic": "Privilege Escalation",
                        }
                    ],
                },
            ],
        },
        "attack_stories": [
            {
                "related_entities": {"hostnames": [hostname]},
                "metadata": {
                    "attack_stages": [
                        "CREDENTIAL_ACCESS",
                        "PRIVILEGE_ESCALATION",
                    ]
                },
            }
        ],
    }


class FakeAnalyzer:
    def __init__(self, routes):
        self.routes = routes
        self.paths = []

    def get_json(self, path):
        self.paths.append(path)
        return self.routes[path]


def test_live_evidence_version_is_explicit():
    assert LIVE_EVIDENCE_VERSION == "isolated-vm-live-evidence-v1"


def test_analyzer_url_requires_http_or_https():
    assert normalize_analyzer_url("http://127.0.0.1:5000/") == "http://127.0.0.1:5000"
    with pytest.raises(ValueError, match="http"):
        normalize_analyzer_url("127.0.0.1:5000")


def test_response_safety_accepts_simulation_and_soar_dry_run():
    safety = response_safety(SAFE_SETTINGS)
    assert safety["safe"] is True
    assert safety["reasons"] == []


def test_response_safety_rejects_live_legacy_response():
    settings = dict(SAFE_SETTINGS, simulation_mode=False)
    safety = response_safety(settings)
    assert safety["safe"] is False
    assert "simulation_mode must be true" in safety["reasons"]


def test_response_safety_rejects_live_soar_when_not_off():
    settings = dict(SAFE_SETTINGS, soar_dry_run=False, soar_mode="AUTO")
    safety = response_safety(settings)
    assert safety["safe"] is False
    assert any("SOAR" in reason for reason in safety["reasons"])


def test_start_capture_records_existing_ids_and_uses_get_only_routes():
    analyzer = FakeAnalyzer({
        "/api/incidents/settings": SAFE_SETTINGS,
        "/api/events?hostname=Y9-LIVE": [
            api_event(100, "LOGON_SUCCESS", 0),
        ],
    })

    baseline = start_capture(
        analyzer.get_json,
        analyzer_url="http://127.0.0.1:5000",
        hostname="Y9-LIVE",
    )

    assert baseline["evidence_version"] == LIVE_EVIDENCE_VERSION
    assert baseline["existing_event_ids"] == ["windows:y9-live:100"]
    assert baseline["response_safety_before"]["safe"] is True
    assert analyzer.paths == [
        "/api/incidents/settings",
        "/api/events?hostname=Y9-LIVE",
    ]


def test_start_capture_refuses_unsafe_analyzer_settings():
    analyzer = FakeAnalyzer({
        "/api/incidents/settings": dict(SAFE_SETTINGS, simulation_mode=False),
    })

    with pytest.raises(RuntimeError, match="not safe"):
        start_capture(
            analyzer.get_json,
            analyzer_url="http://127.0.0.1:5000",
            hostname="Y9-LIVE",
        )


def test_live_snapshot_verification_is_scoped_to_requested_host():
    snapshot = snapshot_for_credential_host("OTHER-HOST")
    verification = verify_live_snapshot(
        snapshot,
        scenario_id="credential-to-privilege",
        hostname="Y9-LIVE",
    )

    assert verification["passed"] is False
    assert "AG-RULE-AUTH-001" in verification["missing_rule_ids"]
    assert verification["attack_story_count"] == 0


def test_finish_capture_validates_only_events_added_after_baseline():
    baseline_event = api_event(100, "LOGON_SUCCESS", 0)
    baseline = {
        "evidence_version": LIVE_EVIDENCE_VERSION,
        "analyzer_url": "http://127.0.0.1:5000",
        "hostname": "Y9-LIVE",
        "started_at": "2026-09-22T09:59:00Z",
        "existing_event_ids": [baseline_event["id"]],
        "existing_event_count": 1,
        "settings_before": SAFE_SETTINGS,
        "response_safety_before": response_safety(SAFE_SETTINGS),
    }
    analyzer = FakeAnalyzer({
        "/api/incidents/settings": SAFE_SETTINGS,
        "/api/events?hostname=Y9-LIVE": [
            baseline_event,
            *credential_events(),
        ],
        f"/api/intelligence?event_limit={INTELLIGENCE_EVENT_LIMIT}":
            snapshot_for_credential_host(),
    })

    evidence = finish_capture(
        analyzer.get_json,
        baseline,
        scenario_id="credential-to-privilege",
    )

    assert evidence["passed"] is True
    assert evidence["new_event_count"] == 5
    assert evidence["local_validation"]["passed"] is True
    assert evidence["live_intelligence_verification"]["passed"] is True
    assert evidence["governance"]["analyzer_requests_are_get_only"] is True
    assert evidence["governance"]["executes_response_actions"] is False


def test_finish_capture_fails_when_live_intelligence_surface_is_missing_evidence():
    baseline = {
        "evidence_version": LIVE_EVIDENCE_VERSION,
        "analyzer_url": "http://127.0.0.1:5000",
        "hostname": "Y9-LIVE",
        "started_at": "2026-09-22T09:59:00Z",
        "existing_event_ids": [],
        "existing_event_count": 0,
        "settings_before": SAFE_SETTINGS,
        "response_safety_before": response_safety(SAFE_SETTINGS),
    }
    analyzer = FakeAnalyzer({
        "/api/incidents/settings": SAFE_SETTINGS,
        "/api/events?hostname=Y9-LIVE": credential_events(),
        f"/api/intelligence?event_limit={INTELLIGENCE_EVENT_LIMIT}": {
            "scope": {},
            "findings": {"rule": [], "correlation": []},
            "attack_stories": [],
        },
    })

    evidence = finish_capture(
        analyzer.get_json,
        baseline,
        scenario_id="credential-to-privilege",
    )

    assert evidence["local_validation"]["passed"] is True
    assert evidence["live_intelligence_verification"]["passed"] is False
    assert evidence["passed"] is False


def test_evidence_bundle_is_json_serializable():
    baseline = {
        "evidence_version": LIVE_EVIDENCE_VERSION,
        "analyzer_url": "http://127.0.0.1:5000",
        "hostname": "Y9-LIVE",
        "started_at": "2026-09-22T09:59:00Z",
        "existing_event_ids": [],
        "existing_event_count": 0,
        "settings_before": SAFE_SETTINGS,
        "response_safety_before": response_safety(SAFE_SETTINGS),
    }
    analyzer = FakeAnalyzer({
        "/api/incidents/settings": SAFE_SETTINGS,
        "/api/events?hostname=Y9-LIVE": credential_events(),
        f"/api/intelligence?event_limit={INTELLIGENCE_EVENT_LIMIT}":
            snapshot_for_credential_host(),
    })

    payload = finish_capture(
        analyzer.get_json,
        baseline,
        scenario_id="credential-to-privilege",
    )
    json.dumps(payload)
