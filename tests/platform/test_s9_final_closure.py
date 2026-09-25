from pathlib import Path

from backend.analyzer.app_authorization import (
    ALL_APPLICATION_ROLES,
    ROLE_ADMINISTRATOR,
    required_roles_for_request,
)
from backend.storage.collector_inventory import (
    DEFAULT_COLLECTOR_STALE_AFTER_SECONDS,
    _liveness_state,
)

ROOT = Path(__file__).resolve().parents[2]


def _read(path):
    return (ROOT / path).read_text(encoding="utf-8-sig")


def test_s9_collector_management_is_read_only():
    source = _read("backend/analyzer/asset_api.py")

    assert '"/api/collectors"' in source
    assert '"/api/collectors/<collector_id>"' in source
    assert ".post(" not in source
    assert ".delete(" not in source
    assert 'methods=["POST"]' not in source
    assert 'methods=["DELETE"]' not in source

    assert required_roles_for_request(
        "/api/collectors", "GET"
    ) == ALL_APPLICATION_ROLES
    assert required_roles_for_request(
        "/api/collectors/collector-1", "GET"
    ) == ALL_APPLICATION_ROLES


def test_s9_inventory_preserves_authority_and_secret_boundary():
    source = _read("backend/storage/collector_inventory.py")

    assert '"authority": "server"' in source
    assert '"collector_reported_operational_only"' in source
    assert '"credential_fingerprint":' not in source
    assert '"certificate_fingerprint":' not in source
    assert '"credential_state":' in source
    assert '"certificate_state":' in source
    assert '"server_queue":' in source
    assert '"assets":' in source


def test_s9_liveness_contract_is_server_derived():
    assert DEFAULT_COLLECTOR_STALE_AFTER_SECONDS == 90.0

    never_seen = _liveness_state(
        status="ENROLLED",
        revoked_at=None,
        last_seen_at=None,
        last_heartbeat_at=None,
        now=None,
        stale_after_seconds=90,
    )
    assert never_seen["state"] == "NEVER_SEEN"
    assert never_seen["authority"] == "server_derived"

    revoked = _liveness_state(
        status="REVOKED",
        revoked_at="2026-09-25T00:00:00Z",
        last_seen_at=None,
        last_heartbeat_at=None,
        now=None,
        stale_after_seconds=90,
    )
    assert revoked["state"] == "REVOKED"


def test_s9_1_runtime_reliability_controls_remain_present():
    app_source = _read("backend/analyzer/app.py")
    runtime_source = _read(
        "backend/analyzer/runtime_reliability.py"
    )
    mtls_source = _read("backend/analyzer/mtls_server.py")

    assert '@app.route("/healthz")' in app_source
    assert '@app.route("/readyz")' in app_source
    assert "validate_analyzer_startup(" in app_source
    assert "validate_analyzer_startup(" in mtls_source
    assert "PRAGMA quick_check(1)" in runtime_source
    assert "CORE_TABLES" in runtime_source
    assert "ingest_stop_event.set()" in mtls_source
    assert "server.server_close()" in mtls_source


def test_s9_2_observability_is_bounded_and_admin_only():
    source = _read(
        "backend/analyzer/operational_observability.py"
    )

    assert '"/api/operations/metrics"' in source
    assert '"/api/operations/diagnostics"' in source
    assert "_SAFE_LOG_FIELDS" in source
    assert "requests_total" in source
    assert "responses_by_class" in source
    assert "latency_ms" in source

    assert required_roles_for_request(
        "/api/operations/metrics", "GET"
    ) == frozenset({ROLE_ADMINISTRATOR})
    assert required_roles_for_request(
        "/api/operations/diagnostics", "GET"
    ) == frozenset({ROLE_ADMINISTRATOR})


def test_s9_supplemental_foundations_have_no_command_execution_surface():
    expected = (
        "S9_3_HEALTH_MONITORING.md",
        "health_monitoring.py",
        "test_health_monitoring.py",
        "S9_4_PRODUCTION_READINESS.md",
        "production_readiness.py",
        "test_production_readiness.py",
        "S9_5_RESILIENCE_RECOVERY.md",
        "resilience_recovery.py",
        "test_resilience_recovery.py",
        "S9_6_SECURITY_VALIDATION.md",
        "security_validation.py",
        "test_security_validation.py",
    )

    for path in expected:
        assert (ROOT / path).is_file()

    for path in (
        "health_monitoring.py",
        "production_readiness.py",
        "resilience_recovery.py",
        "security_validation.py",
    ):
        source = _read(path)
        assert "subprocess" not in source
        assert "powershell" not in source.lower()
        assert "os.system" not in source
        assert "requests." not in source
