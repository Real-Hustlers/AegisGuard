from backend.analyzer.correlation import CorrelationEngine
from backend.analyzer.detection.contracts import CanonicalEvent, DetectionType, Severity
from backend.analyzer.detection.rule_engine import RuleEngine
from backend.analyzer.ml import FEATURE_COLUMNS, MLEngine, build_feature_frame


def event(i, event_type, minute=0, **kwargs):
    return CanonicalEvent(
        event_id=f"LOG-{i:04d}",
        timestamp=f"2026-09-21T10:{minute:02d}:00Z",
        event_type=event_type,
        severity=kwargs.pop("severity", "LOW"),
        hostname=kwargs.pop("hostname", "WIN-TEST"),
        user=kwargs.pop("user", "alice"),
        source_ip=kwargs.pop("source_ip", "10.0.0.5"),
        process=kwargs.pop("process", ""),
        file_path=kwargs.pop("file_path", ""),
        **kwargs,
    )


def test_rule_engine_marks_failed_login_as_rule_not_ml():
    finding = RuleEngine().detect(event(1, "FAILED_LOGIN"))
    assert finding is not None
    assert finding.detection_type is DetectionType.RULE
    assert finding.rule_id == "AG-RULE-AUTH-001"
    assert finding.model_version is None
    assert finding.metadata["classification_label"] == "BRUTE_FORCE"


def test_rule_engine_does_not_emit_benign_success_as_detection():
    assert RuleEngine().detect(event(2, "LOGON_SUCCESS")) is None


class FakeModel:
    def __init__(self, encoded=1, probabilities=(0.1, 0.9)):
        self.encoded = encoded
        self.probabilities = probabilities
        self.last_columns = None

    def predict(self, frame):
        self.last_columns = tuple(frame.columns)
        return [self.encoded]

    def predict_proba(self, frame):
        return [self.probabilities]


class FakeEncoder:
    def __init__(self, label="MALWARE"):
        self.label = label

    def inverse_transform(self, values):
        return [self.label for _ in values]


def test_ml_engine_is_model_only_and_emits_versioned_ml_finding():
    model = FakeModel()
    engine = MLEngine(
        model=model,
        encoder=FakeEncoder("MALWARE"),
        model_name="aegis-threat-classifier",
        model_version="0.1.0-candidate.1",
    )
    finding = engine.detect([event(3, "FILE_MODIFIED", severity="CRITICAL")])
    assert finding is not None
    assert finding.detection_type is DetectionType.ML
    assert finding.model_version == "0.1.0-candidate.1"
    assert finding.confidence == 0.9
    assert finding.severity is Severity.CRITICAL
    assert model.last_columns == FEATURE_COLUMNS


def test_ml_engine_normal_prediction_is_observable_but_not_a_detection():
    engine = MLEngine(
        model=FakeModel(encoded=0, probabilities=(0.97, 0.03)),
        encoder=FakeEncoder("NORMAL"),
        model_name="aegis-threat-classifier",
        model_version="0.1.0-candidate.1",
    )
    prediction = engine.predict([event(4, "LOGON_SUCCESS")])
    assert prediction.prediction == "NORMAL"
    assert prediction.confidence == 0.97
    assert engine.detect([event(4, "LOGON_SUCCESS")]) is None


def test_feature_schema_preserves_legacy_18_feature_order():
    frame = build_feature_frame([
        event(5, "FAILED_LOGIN", severity="HIGH"),
        event(6, "LOGON_SUCCESS", source_ip="10.0.0.8"),
    ])
    assert tuple(frame.columns) == FEATURE_COLUMNS
    assert frame.iloc[0]["FAILED_LOGIN"] == 1
    assert frame.iloc[0]["TOTAL_EVENTS"] == 2
    assert frame.iloc[0]["UNIQUE_SOURCE_IPS"] == 2


def correlation_names(events):
    findings = CorrelationEngine().correlate(events)
    assert all(f.detection_type is DetectionType.CORRELATION for f in findings)
    assert all(f.model_version is None for f in findings)
    return {finding.name for finding in findings}


def test_correlation_brute_force_parity():
    names = correlation_names([
        event(10, "FAILED_LOGIN", 0),
        event(11, "FAILED_LOGIN", 1),
        event(12, "FAILED_LOGIN", 2),
        event(13, "LOGON_SUCCESS", 3),
    ])
    assert "Multiple Failed Login Attempts" in names
    assert "Possible Brute Force Attack" in names


def test_correlation_privilege_escalation_parity():
    names = correlation_names([
        event(20, "LOGON_SUCCESS", 0, user="admin"),
        event(21, "ADMIN_GROUP_ADDED", 1, user="admin"),
    ])
    assert "Privilege Escalation" in names


def test_correlation_malware_execution_parity():
    names = correlation_names([
        event(30, "PROCESS_CREATED", 0, process="powershell.exe"),
        event(31, "NETWORK_CONNECTION", 1, process="powershell.exe"),
    ])
    assert "Possible Malware Execution" in names


def test_correlation_reconnaissance_parity():
    names = correlation_names([
        event(40, "LOCAL_GROUP_ENUMERATION", 0),
        event(41, "PROCESS_CREATED", 1, process="cmd.exe"),
        event(42, "NETWORK_CONNECTION", 2),
    ])
    assert "Reconnaissance Activity" in names


def test_correlation_lateral_movement_parity():
    names = correlation_names([
        event(50, "LOGON_SUCCESS", 0),
        event(51, "NETWORK_CONNECTION", 1),
        event(52, "PROCESS_CREATED", 2, process="wmic.exe"),
    ])
    assert "Possible Lateral Movement" in names


def test_correlation_persistence_parity():
    names = correlation_names([
        event(60, "USER_CREATED", 0, user="newuser"),
        event(61, "PASSWORD_CHANGED", 1, user="newuser"),
        event(62, "LOGON_SUCCESS", 2, user="newuser"),
    ])
    assert "Possible Persistence Established" in names


def test_correlation_exfiltration_parity():
    events = [event(70 + i, "FILE_ACCESS", i, file_path=f"C:/secret{i}.txt") for i in range(5)]
    events.append(event(80, "NETWORK_CONNECTION", 5))
    assert "Possible Data Exfiltration" in correlation_names(events)


def test_correlation_ransomware_parity():
    events = [event(90, "PROCESS_CREATED", 0, process="encryptor.exe")]
    events.extend(event(90 + i, "FILE_ACCESS", i, file_path=f"C:/file{i}.txt") for i in range(1, 11))
    assert "Possible Ransomware Activity" in correlation_names(events)
