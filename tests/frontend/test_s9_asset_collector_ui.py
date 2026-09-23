from html import unescape
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "static" / "js" / "dashboard.js"
TEMPLATE = ROOT / "templates" / "index.html"


def dashboard_source():
    return DASHBOARD.read_text(encoding="utf-8")


def template_source():
    return TEMPLATE.read_text(encoding="utf-8")


def test_asset_management_uses_authoritative_collector_api():
    source = dashboard_source()

    assert "fetch('/api/collectors')" in source
    assert "fetch('/api/devices')" not in source


def test_collector_and_asset_state_are_rendered():
    source = dashboard_source()

    assert "collector.identity" in source
    assert "collector.server_observed" in source
    assert "collector.collector_reported" in source
    assert "collector.server_queue" in source
    assert "collector.assets" in source


def test_security_and_operational_state_are_separate():
    source = dashboard_source()

    assert "credential_state" in source
    assert "certificate_state" in source
    assert "mtls_verified" in source

    assert "transport_status" in source
    assert "pending_batches" in source
    assert "checkpoint" in source


def test_frontend_never_requests_sensitive_fingerprints():
    source = dashboard_source()

    assert "credential_fingerprint" not in source
    assert "certificate_fingerprint" not in source


def test_asset_management_workspace_explains_authority_boundary():
    source = unescape(
        template_source()
    )

    assert "Asset & Collector Management" in source
    assert "Server-authoritative trust state" in source
    assert "collector-reported operational health" in source


def test_asset_management_has_enterprise_summary_fields():
    source = template_source()

    for expected in (
        "assetCollectorCount",
        "assetEnrolledCount",
        "assetRevokedCount",
        "assetBacklogCount",
        "deviceGrid",
    ):
        assert expected in source


def test_legacy_severity_is_not_used_as_collector_health():
    source = dashboard_source()

    render_start = source.index(
        "function renderCollectors("
    )
    render_end = source.index(
        "function renderAlerts(",
        render_start,
    )

    renderer = source[
        render_start:render_end
    ]

    assert "severity" not in renderer.lower()
    assert "critical event" not in renderer.lower()


def test_liveness_states_are_explicit_and_server_derived():
    source = dashboard_source()

    assert "collector.liveness" in source

    for state in (
        "CURRENT",
        "STALE",
        "NEVER_SEEN",
        "REVOKED",
    ):
        assert state in source

    assert "Liveness" in source
