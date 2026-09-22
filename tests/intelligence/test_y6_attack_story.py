from datetime import timedelta

import pytest

from backend.analyzer.correlation.story import (
    AttackStage,
    AttackStoryBuilder,
    STORY_VERSION,
    build_attack_stories,
)
from backend.analyzer.detection.contracts import (
    DetectionFinding,
    DetectionType,
    MITREMapping,
    Severity,
)


def mapping(technique_id, technique, tactic):
    return MITREMapping(technique_id=technique_id, technique=technique, tactic=tactic)


def finding(
    n,
    *,
    minute,
    correlation_id=None,
    tactic=None,
    hostname="WIN-Y6",
    user="alice",
    source_ip="10.0.0.5",
    severity=Severity.HIGH,
    confidence=0.8,
    finding_id=None,
):
    mitre = ()
    if tactic:
        mitre = (mapping(f"T{n:04d}", f"Technique {n}", tactic),)
    return DetectionFinding(
        finding_id=finding_id or f"FND-Y6-{n:03d}",
        event_ids=(f"EVT-Y6-{n:03d}",),
        detection_type=DetectionType.CORRELATION if correlation_id else DetectionType.RULE,
        name=f"Finding {n}",
        severity=severity,
        confidence=confidence,
        reason="test evidence",
        timestamp=f"2026-09-22T10:{minute:02d}:00Z",
        prediction_source="test",
        correlation_id=correlation_id,
        mitre=mitre,
        evidence=(
            {
                "event_id": f"EVT-Y6-{n:03d}",
                "hostname": hostname,
                "user": user,
                "source_ip": source_ip,
                "process": "powershell.exe" if n % 2 else "cmd.exe",
            },
        ),
        metadata={"hostname": hostname} if hostname else {},
    )


def test_story_version_is_explicit():
    assert STORY_VERSION == "attack-story-v1"


def test_single_stage_does_not_create_multi_stage_candidate():
    assert build_attack_stories([
        finding(1, minute=0, correlation_id="AG-CORR-AUTH-001B"),
        finding(2, minute=1, correlation_id="AG-CORR-AUTH-001A"),
    ]) == ()


def test_two_distinct_stages_create_incident_candidate():
    candidates = build_attack_stories([
        finding(1, minute=0, correlation_id="AG-CORR-AUTH-001B"),
        finding(2, minute=3, correlation_id="AG-CORR-PRIV-001A"),
    ])
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.metadata["attack_stages"] == (
        AttackStage.CREDENTIAL_ACCESS.value,
        AttackStage.PRIVILEGE_ESCALATION.value,
    )
    assert candidate.metadata["story_version"] == STORY_VERSION


def test_story_timeline_is_chronological_even_when_input_is_not():
    late = finding(2, minute=8, correlation_id="AG-CORR-PERSIST-001")
    early = finding(1, minute=1, correlation_id="AG-CORR-AUTH-001B")
    candidate = build_attack_stories([late, early])[0]
    assert candidate.finding_ids == (early.finding_id, late.finding_id)
    assert [item["finding_id"] for item in candidate.metadata["timeline"]] == [
        early.finding_id,
        late.finding_id,
    ]


def test_candidate_id_is_deterministic_regardless_of_input_order():
    a = finding(1, minute=1, correlation_id="AG-CORR-AUTH-001B")
    b = finding(2, minute=2, correlation_id="AG-CORR-DISC-001")
    forward = build_attack_stories([a, b])[0]
    reverse = build_attack_stories([b, a])[0]
    assert forward.candidate_id == reverse.candidate_id


def test_findings_on_different_hosts_are_not_stitched_together():
    candidates = build_attack_stories([
        finding(1, minute=0, correlation_id="AG-CORR-AUTH-001B", hostname="HOST-A"),
        finding(2, minute=1, correlation_id="AG-CORR-PRIV-001A", hostname="HOST-B"),
    ])
    assert candidates == ()


def test_two_hosts_each_with_two_stages_produce_two_candidates():
    candidates = build_attack_stories([
        finding(1, minute=0, correlation_id="AG-CORR-AUTH-001B", hostname="HOST-A"),
        finding(2, minute=1, correlation_id="AG-CORR-PRIV-001A", hostname="HOST-A"),
        finding(3, minute=2, correlation_id="AG-CORR-DISC-001", hostname="HOST-B"),
        finding(4, minute=3, correlation_id="AG-CORR-PERSIST-001", hostname="HOST-B"),
    ])
    assert len(candidates) == 2
    assert {c.metadata["grouping_entity"]["value"] for c in candidates} == {"HOST-A", "HOST-B"}


def test_story_window_prevents_unbounded_historical_stitching():
    early = finding(1, minute=0, correlation_id="AG-CORR-AUTH-001B")
    late = DetectionFinding(
        **{
            **finding(2, minute=1, correlation_id="AG-CORR-IMPACT-001").__dict__,
            "timestamp": "2026-09-24T10:01:00Z",
        }
    )
    assert AttackStoryBuilder(story_window=timedelta(hours=24)).build([early, late]) == ()


def test_maximum_severity_and_confidence_are_preserved_without_inflation():
    candidate = build_attack_stories([
        finding(1, minute=0, correlation_id="AG-CORR-AUTH-001B", severity=Severity.HIGH, confidence=0.80),
        finding(2, minute=2, correlation_id="AG-CORR-IMPACT-001", severity=Severity.CRITICAL, confidence=0.98),
    ])[0]
    assert candidate.severity is Severity.CRITICAL
    assert candidate.confidence == 0.98


def test_mitre_mappings_are_deduplicated_in_timeline_order():
    shared = mapping("T1110", "Brute Force", "Credential Access")
    a = finding(1, minute=0, correlation_id="AG-CORR-AUTH-001B")
    b = finding(2, minute=1, correlation_id="AG-CORR-PRIV-001A")
    a = DetectionFinding(**{**a.__dict__, "mitre": (shared,)})
    b = DetectionFinding(**{**b.__dict__, "mitre": (shared, mapping("T1098.007", "Account Manipulation: Additional Local or Domain Groups", "Privilege Escalation"))})
    candidate = build_attack_stories([a, b])[0]
    assert [item.technique_id for item in candidate.mitre] == ["T1110", "T1098.007"]


def test_related_entities_are_collected_for_investigation():
    candidate = build_attack_stories([
        finding(1, minute=0, correlation_id="AG-CORR-AUTH-001B", user="alice", source_ip="10.0.0.5"),
        finding(2, minute=1, correlation_id="AG-CORR-DISC-001", user="bob", source_ip="10.0.0.7"),
    ])[0]
    assert candidate.related_entities["hostnames"] == ("WIN-Y6",)
    assert candidate.related_entities["users"] == ("alice", "bob")
    assert candidate.related_entities["source_ips"] == ("10.0.0.5", "10.0.0.7")


def test_rule_or_ml_finding_can_contribute_when_mitre_tactic_is_specific():
    candidates = build_attack_stories([
        finding(1, minute=0, tactic="Credential Access"),
        finding(2, minute=1, correlation_id="AG-CORR-PERSIST-001"),
    ])
    assert len(candidates) == 1
    assert candidates[0].metadata["attack_stages"] == (
        AttackStage.CREDENTIAL_ACCESS.value,
        AttackStage.PERSISTENCE.value,
    )


def test_generic_unmapped_finding_does_not_create_a_stage():
    generic = finding(1, minute=0)
    persistence = finding(2, minute=1, correlation_id="AG-CORR-PERSIST-001")
    assert build_attack_stories([generic, persistence]) == ()


def test_duplicate_finding_ids_are_rejected():
    with pytest.raises(ValueError, match="duplicate finding_id"):
        build_attack_stories([
            finding(1, minute=0, correlation_id="AG-CORR-AUTH-001B", finding_id="DUP"),
            finding(2, minute=1, correlation_id="AG-CORR-PERSIST-001", finding_id="DUP"),
        ])


def test_ambiguous_multi_host_finding_is_not_used_as_grouping_evidence():
    ambiguous = finding(1, minute=0, correlation_id="AG-CORR-AUTH-001B")
    ambiguous = DetectionFinding(
        **{
            **ambiguous.__dict__,
            "metadata": {},
            "evidence": (
                {"hostname": "HOST-A", "source_ip": "10.0.0.1", "user": "alice"},
                {"hostname": "HOST-B", "source_ip": "10.0.0.2", "user": "alice"},
            ),
        }
    )
    persistence = finding(2, minute=1, correlation_id="AG-CORR-PERSIST-001", hostname="HOST-A")
    assert build_attack_stories([ambiguous, persistence]) == ()


def test_invalid_builder_configuration_is_rejected():
    with pytest.raises(ValueError, match="minimum_stages"):
        AttackStoryBuilder(minimum_stages=1)
    with pytest.raises(ValueError, match="story_window"):
        AttackStoryBuilder(story_window=timedelta(0))
