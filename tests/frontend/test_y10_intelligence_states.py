from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

INDEX = ROOT / "templates" / "index.html"
DASHBOARD = ROOT / "static" / "js" / "dashboard.js"
INTELLIGENCE = ROOT / "static" / "js" / "intelligence_ui.js"


def read(path):
    return path.read_text(encoding="utf-8")


def test_intelligence_workspace_has_explicit_initial_loading_state():
    html = read(INDEX)

    assert 'id="intelDataStatus"' in html
    assert "WAITING FOR DATA" in html
    assert "Waiting for structured detection-source data." in html
    assert "Waiting for ML telemetry." in html


def test_empty_detection_state_is_explicit():
    source = read(INTELLIGENCE)

    assert (
        "The current API does not yet expose structured "
        "detection_type/source_engine fields."
    ) in source


def test_empty_mitre_state_is_explicit():
    source = read(INTELLIGENCE)

    assert (
        "No structured MITRE ATT&amp;CK mapping is present "
        "in the data currently available to this view."
    ) in source


def test_empty_attack_story_state_is_explicit():
    source = read(INTELLIGENCE)

    assert (
        "No structured multi-stage attack story is exposed "
        "by the current incident API."
    ) in source


def test_snapshot_error_distinguishes_degraded_from_stale():
    source = read(INTELLIGENCE)

    assert "state.snapshotAuthoritative" in source
    assert "'SNAPSHOT STALE'" in source
    assert "'SNAPSHOT DEGRADED'" in source
    assert "badge badge-high" in source


def test_snapshot_status_distinguishes_complete_and_truncated_data():
    source = read(INTELLIGENCE)

    assert "scope.truncated" in source
    assert "SNAPSHOT ${scope.events_analyzed || 0}/${scope.total_events || 0}" in source
    assert "'READ-ONLY SNAPSHOT'" in source


def test_dashboard_routes_failed_intelligence_fetch_to_degraded_renderer():
    source = read(DASHBOARD)

    assert "if (!response.ok)" in source
    assert "Intelligence snapshot failed" in source
    assert "AegisIntelligenceUI.renderError(error)" in source
