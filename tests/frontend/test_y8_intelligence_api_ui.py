from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "static" / "js" / "dashboard.js"
INTELLIGENCE = ROOT / "static" / "js" / "intelligence_ui.js"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_dashboard_fetches_read_only_intelligence_snapshot():
    source = read(DASHBOARD)
    assert "fetch('/api/intelligence?event_limit=500')" in source
    assert "loadIntelligenceSnapshot()" in source


def test_intelligence_fetch_checks_http_status():
    source = read(DASHBOARD)
    assert "if (!response.ok)" in source
    assert "Intelligence snapshot failed" in source


def test_successful_snapshot_is_given_to_intelligence_ui():
    assert "AegisIntelligenceUI.renderSnapshot(snapshot)" in read(DASHBOARD)


def test_snapshot_failure_has_explicit_degraded_path():
    assert "AegisIntelligenceUI.renderError(error)" in read(DASHBOARD)


def test_intelligence_ui_marks_snapshot_authoritative():
    source = read(INTELLIGENCE)
    assert "snapshotAuthoritative" in source
    assert "state.snapshotAuthoritative = true" in source


def test_legacy_callbacks_do_not_overwrite_authoritative_snapshot():
    source = read(INTELLIGENCE)
    assert source.count("if (state.snapshotAuthoritative) return;") >= 2


def test_snapshot_uses_structured_findings_and_attack_stories():
    source = read(INTELLIGENCE)
    assert "payload.findings" in source
    assert "payload.attack_stories" in source
    assert "findings.correlation" in source
    assert "findings.rule" in source


def test_legacy_ml_telemetry_is_labeled():
    source = read(INTELLIGENCE)
    assert "legacy_ml_telemetry" in source
    assert "Legacy persisted ML telemetry" in source
    assert "model_identity_available" in source


def test_intelligence_ui_still_performs_no_network_requests_itself():
    source = read(INTELLIGENCE)
    assert "fetch(" not in source
    assert "XMLHttpRequest" not in source
