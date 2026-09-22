from backend.analyzer.ingestion.classifier import _build_feature_vector


LEGACY_MODEL_FEATURES = (
    "FAILED_LOGIN",
    "SUCCESSFUL_LOGIN",
    "AUTHENTICATION_FAILURE",
    "SUDO_COMMAND",
    "PRIVILEGE_ESCALATION",
    "FILE_MODIFIED",
    "FILE_DELETED",
    "USB_CONNECTED",
    "DEFENDER_ALERT",
    "PASSWORD_CHANGED",
    "USER_CREATED",
    "USER_DELETED",
    "KERNEL_EVENT",
    "TOTAL_EVENTS",
    "HIGH_EVENTS",
    "CRITICAL_EVENTS",
    "UNIQUE_USERS",
    "UNIQUE_SOURCE_IPS",
)


def test_logon_success_preserves_legacy_ml_feature_contract():
    frame = _build_feature_vector([
        {
            "event_type": "LOGON_SUCCESS",
            "user": "AegisY9Lab",
            "source_ip": "::1",
            "severity": "Information",
        }
    ])

    assert tuple(frame.columns) == LEGACY_MODEL_FEATURES
    assert "LOGON_SUCCESS" not in frame.columns
    assert frame.iloc[0]["SUCCESSFUL_LOGIN"] == 1
