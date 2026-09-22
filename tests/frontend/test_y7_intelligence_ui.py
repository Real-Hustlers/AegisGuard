from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INDEX = ROOT / "templates" / "index.html"
DASHBOARD = ROOT / "static" / "js" / "dashboard.js"
SHELL = ROOT / "static" / "js" / "frontend_shell.js"
INTELLIGENCE = ROOT / "static" / "js" / "intelligence_ui.js"
CSS = ROOT / "static" / "css" / "aegisguard-enterprise.css"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_intelligence_workspace_is_present_in_navigation_and_template():
    html = read(INDEX)
    assert 'data-target="view-intelligence"' in html
    assert 'id="view-intelligence"' in html
    assert "Security Intelligence Workspace" in html


def test_intelligence_asset_is_loaded():
    assert "js/intelligence_ui.js" in read(INDEX)


def test_intelligence_renderer_has_no_network_calls():
    source = read(INTELLIGENCE)
    assert "fetch(" not in source
    assert "XMLHttpRequest" not in source


def test_dashboard_passes_existing_data_to_intelligence_renderer():
    source = read(DASHBOARD)
    assert "AegisIntelligenceUI.renderDashboard(dashboardData, alerts, events)" in source
    assert "AegisIntelligenceUI.renderIncidents(incidents)" in source


def test_detection_sources_are_only_read_from_structured_fields():
    source = read(INTELLIGENCE)
    assert "record && record.detection_type" in source
    assert "record && record.source_engine" in source
    assert "record && record.prediction_source" in source
    assert "are not guessed" in source


def test_mitre_workspace_supports_current_mapping_shapes():
    source = read(INTELLIGENCE)
    assert "technique_id" in source
    assert "technique_name" in source
    assert "object.mitre" in source
    assert 'id="intelMitreCoverage"' in read(INDEX)


def test_ml_workspace_uses_existing_dashboard_summary():
    source = read(INTELLIGENCE)
    assert "dashboard.ml_summary" in source
    assert "model_version" in source
    assert "feature_schema_version" in source


def test_attack_story_renderer_accepts_y6_style_structured_metadata():
    source = read(INTELLIGENCE)
    assert "incident && incident.attack_story" in source
    assert "metadata.attack_story" in source
    assert "report.attack_story" in source
    assert "entry.stages.length >= 2" in source


def test_attack_story_has_explicit_empty_state():
    assert "No structured multi-stage attack story" in read(INTELLIGENCE)


def test_incident_details_are_null_safe():
    source = read(DASHBOARD)
    assert "const report = incident.incident_report || {};" in source
    assert "Array.isArray(incident.playbook_steps)" in source
    assert "incident.incident_report.threat_type" not in source
    assert "incident.playbook_steps.join" not in source


def test_legacy_mitre_name_shape_is_supported_in_incident_details():
    source = read(DASHBOARD)
    assert "mitre.technique_name || mitre.technique || 'Unknown'" in source


def test_enterprise_css_contains_intelligence_workspace_rules():
    css = read(CSS)
    assert "Y7 Slice 2: Intelligence workspace" in css
    assert ".ag-intel-kpis" in css
    assert ".ag-story-stage" in css


def test_mobile_menu_glyph_is_ascii_safe_html_entity():
    assert "&#9776;" in read(SHELL)
