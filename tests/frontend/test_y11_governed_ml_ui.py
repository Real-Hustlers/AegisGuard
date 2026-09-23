from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INTELLIGENCE = ROOT / "static" / "js" / "intelligence_ui.js"


def read() -> str:
    return INTELLIGENCE.read_text(encoding="utf-8")


def test_ui_tracks_governed_runtime_and_findings_separately():
    source = read()

    assert "governedMlRuntime" in source
    assert "governedMlFindings" in source
    assert "legacyMlTelemetry" in source


def test_snapshot_consumes_governed_runtime_and_ml_findings():
    source = read()

    assert "payload.governed_ml_runtime" in source
    assert "findings.ml" in source
    assert "state.governedMlRuntime = runtime" in source
    assert "state.governedMlFindings = governedFindings" in source


def test_runtime_states_are_explicit_in_ui():
    source = read()

    assert "AVAILABLE" in source
    assert "UNAVAILABLE" in source
    assert "DEGRADED" in source


def test_governed_ml_identity_is_rendered():
    source = read()

    assert "Governed ML Runtime" in source
    assert "Promoted Model" in source
    assert "Model Version" in source
    assert "Feature Schema" in source


def test_governed_finding_prediction_and_confidence_are_rendered():
    source = read()

    assert "Threat Prediction" in source
    assert "Confidence" in source
    assert "findingMetadata.prediction" in source
    assert "primaryFinding.confidence" in source
    assert "Number(primaryFinding.confidence) * 100" in source


def test_legacy_telemetry_remains_explicitly_separate():
    source = read()

    assert "Legacy ML Telemetry" in source
    assert "Legacy persisted ML telemetry" in source
    assert "model_identity_available" in source


def test_intelligence_renderer_remains_network_free():
    source = read()

    assert "fetch(" not in source
    assert "XMLHttpRequest" not in source
