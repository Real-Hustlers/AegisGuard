from backend.analyzer.correlation import CorrelationEngine
from backend.analyzer.detection.contracts import CanonicalEvent
from backend.analyzer.detection.rule_engine import RuleEngine
from backend.analyzer.ingestion.mitre.mitre_mapper import MitreMapper
from backend.analyzer.ingestion.mitre_mapper import get_mitre_mapping
from backend.analyzer.mitre import (
    ATTACK_CATALOG_VERSION,
    legacy_mapping_for_label,
    mappings_for_label,
)
from backend.analyzer.ml import MLEngine


def event(i, event_type, minute=0, **kwargs):
    return CanonicalEvent(
        event_id=f"Y5-{i:04d}",
        timestamp=f"2026-09-22T10:{minute:02d}:00Z",
        event_type=event_type,
        severity=kwargs.pop("severity", "LOW"),
        hostname=kwargs.pop("hostname", "WIN-Y5"),
        user=kwargs.pop("user", "alice"),
        source_ip=kwargs.pop("source_ip", "10.0.0.5"),
        process=kwargs.pop("process", ""),
        file_path=kwargs.pop("file_path", ""),
        **kwargs,
    )


def technique_ids(finding):
    return {mapping.technique_id for mapping in finding.mitre}


class FakeModel:
    def __init__(self, probabilities=(0.05, 0.95)):
        self.probabilities = probabilities

    def predict(self, frame):
        return [1]

    def predict_proba(self, frame):
        return [self.probabilities]


class FakeEncoder:
    def __init__(self, label):
        self.label = label

    def inverse_transform(self, values):
        return [self.label for _ in values]


def ml_finding(label):
    return MLEngine(
        model=FakeModel(),
        encoder=FakeEncoder(label),
        model_name="aegis-threat-classifier",
        model_version="0.5.0-test",
    ).detect([event(1, "FAILED_LOGIN", severity="HIGH")])


def correlation_findings(events):
    return {finding.correlation_id: finding for finding in CorrelationEngine().correlate(events)}


def test_catalog_has_auditable_version():
    assert ATTACK_CATALOG_VERSION == "enterprise-attack-2026-05"


def test_brute_force_label_maps_to_t1110():
    mappings = mappings_for_label("brute_force")
    assert mappings[0].technique_id == "T1110"
    assert mappings[0].technique == "Brute Force"


def test_current_firewall_mapping_uses_t1686_defense_impairment():
    mapping = mappings_for_label("FIREWALL_DISABLED")[0]
    assert mapping.technique_id == "T1686"
    assert mapping.technique == "Disable or Modify System Firewall"
    assert mapping.tactic == "Defense Impairment"


def test_current_port_scan_mapping_uses_network_service_discovery_name():
    mapping = mappings_for_label("PORT_SCAN")[0]
    assert mapping.technique_id == "T1046"
    assert mapping.technique == "Network Service Discovery"


def test_generic_malware_does_not_fabricate_a_technique():
    assert mappings_for_label("MALWARE") == ()


def test_legacy_mapper_delegates_to_canonical_catalog():
    expected = legacy_mapping_for_label("BRUTE_FORCE")
    assert MitreMapper().get_mapping("BRUTE_FORCE") == expected
    assert get_mitre_mapping("BRUTE_FORCE") == expected


def test_legacy_unknown_and_normal_are_explicit_without_fake_attack_id():
    assert get_mitre_mapping("NOT_A_REAL_LABEL")["technique_id"] == "N/A"
    normal = get_mitre_mapping("NORMAL")
    assert normal == {
        "technique_id": "N/A",
        "technique": "No Threat",
        "tactic": "None",
    }


def test_rule_engine_attaches_brute_force_mapping():
    finding = RuleEngine().detect(event(10, "FAILED_LOGIN"))
    assert finding is not None
    assert technique_ids(finding) == {"T1110"}


def test_rule_engine_generic_defender_alert_has_no_fabricated_mapping():
    finding = RuleEngine().detect(event(11, "DEFENDER_ALERT", severity="CRITICAL"))
    assert finding is not None
    assert finding.mitre == ()


def test_ml_engine_uses_same_canonical_label_mapping():
    finding = ml_finding("BRUTE_FORCE")
    assert finding is not None
    assert technique_ids(finding) == {"T1110"}


def test_ml_generic_malware_has_no_fabricated_mapping():
    finding = ml_finding("MALWARE")
    assert finding is not None
    assert finding.mitre == ()


def test_correlation_brute_force_maps_to_t1110():
    findings = correlation_findings([
        event(20, "FAILED_LOGIN", 0),
        event(21, "FAILED_LOGIN", 1),
        event(22, "FAILED_LOGIN", 2),
        event(23, "LOGON_SUCCESS", 3),
    ])
    assert technique_ids(findings["AG-CORR-AUTH-001B"]) == {"T1110"}


def test_correlation_admin_group_change_uses_specific_t1098_007():
    findings = correlation_findings([
        event(30, "LOGON_SUCCESS", 0, user="admin"),
        event(31, "ADMIN_GROUP_ADDED", 1, user="admin"),
    ])
    assert technique_ids(findings["AG-CORR-PRIV-001A"]) == {"T1098.007"}


def test_correlation_reconnaissance_maps_local_group_discovery():
    findings = correlation_findings([
        event(40, "LOCAL_GROUP_ENUMERATION", 0),
        event(41, "PROCESS_CREATED", 1, process="cmd.exe"),
        event(42, "NETWORK_CONNECTION", 2),
    ])
    assert technique_ids(findings["AG-CORR-DISC-001"]) == {"T1069.001"}


def test_correlation_persistence_maps_create_account():
    findings = correlation_findings([
        event(50, "USER_CREATED", 0, user="newuser"),
        event(51, "PASSWORD_CHANGED", 1, user="newuser"),
        event(52, "LOGON_SUCCESS", 2, user="newuser"),
    ])
    assert technique_ids(findings["AG-CORR-PERSIST-001"]) == {"T1136"}


def test_correlation_file_collection_maps_t1005():
    events = [event(60 + i, "FILE_ACCESS", i, file_path=f"C:/secret{i}.txt") for i in range(5)]
    events.append(event(70, "NETWORK_CONNECTION", 5))
    findings = correlation_findings(events)
    assert technique_ids(findings["AG-CORR-EXFIL-001"]) == {"T1005"}


def test_correlation_ransomware_maps_t1486():
    events = [event(80, "PROCESS_CREATED", 0, process="encryptor.exe")]
    events.extend(
        event(80 + i, "FILE_ACCESS", i, file_path=f"C:/file{i}.txt")
        for i in range(1, 11)
    )
    findings = correlation_findings(events)
    assert technique_ids(findings["AG-CORR-IMPACT-001"]) == {"T1486"}


def test_generic_lateral_correlation_is_not_forced_to_a_technique():
    findings = correlation_findings([
        event(100, "LOGON_SUCCESS", 0),
        event(101, "NETWORK_CONNECTION", 1),
        event(102, "PROCESS_CREATED", 2, process="wmic.exe"),
    ])
    assert findings["AG-CORR-LAT-001"].mitre == ()
