from pathlib import Path

from backend.analyzer.intelligence.ml_runtime import (
    DEFAULT_GOVERNED_MODEL_NAME,
    GovernedMLRuntimeStatus,
    create_configured_ml_runtime_provider,
)


ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "backend" / "analyzer" / "app.py"


def test_default_runtime_configuration_is_safely_unavailable(
    tmp_path,
):
    registry_root = tmp_path / "default-registry"

    provider = create_configured_ml_runtime_provider(
        default_registry_root=registry_root,
        environ={},
    )

    runtime = provider()

    assert (
        runtime.status
        is GovernedMLRuntimeStatus.UNAVAILABLE
    )
    assert runtime.available is False
    assert runtime.model_name == DEFAULT_GOVERNED_MODEL_NAME
    assert runtime.reason == "no promoted model"
    assert registry_root.exists()


def test_environment_can_override_registry_and_model_name(
    tmp_path,
):
    configured_root = tmp_path / "configured-registry"

    provider = create_configured_ml_runtime_provider(
        default_registry_root=tmp_path / "ignored",
        environ={
            "AEGISGUARD_ML_REGISTRY_PATH": str(configured_root),
            "AEGISGUARD_ML_MODEL_NAME": "enterprise-threat-model",
        },
    )

    runtime = provider()

    assert (
        runtime.status
        is GovernedMLRuntimeStatus.UNAVAILABLE
    )
    assert runtime.model_name == "enterprise-threat-model"
    assert configured_root.exists()


def test_blank_model_name_falls_back_to_governed_default(
    tmp_path,
):
    provider = create_configured_ml_runtime_provider(
        default_registry_root=tmp_path / "registry",
        environ={
            "AEGISGUARD_ML_MODEL_NAME": "   ",
        },
    )

    runtime = provider()

    assert runtime.model_name == DEFAULT_GOVERNED_MODEL_NAME


def test_analyzer_app_wires_runtime_provider_into_intelligence_api():
    source = APP.read_text(encoding="utf-8")

    assert "create_configured_ml_runtime_provider" in source
    assert "governed_ml_runtime_provider" in source

    compact = "".join(source.split())

    assert (
        "ml_runtime_provider=governed_ml_runtime_provider"
        in compact
    )

    # Saran-owned authorization must remain installed.
    assert "install_application_authorization(" in source
    assert "install_browser_security_headers(app)" in source
