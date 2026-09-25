import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load_builder():
    path = (
        ROOT
        / "scripts"
        / "build_windows_offline_bundle.py"
    )

    spec = importlib.util.spec_from_file_location(
        "s14_bundle_builder",
        path,
    )
    module = importlib.util.module_from_spec(
        spec
    )

    assert spec.loader is not None
    spec.loader.exec_module(
        module
    )

    return module


def test_s14_recovery_tool_is_source_free_bundle_artifact():
    module = _load_builder()

    destinations = {
        destination
        for destination, _source
        in module.BUNDLE_PAYLOAD
    }

    assert (
        "bin/AegisGuardRecovery.exe"
        in destinations
    )

    assert not any(
        destination.endswith(
            ".py"
        )
        for destination
        in destinations
    )


def test_s14_recovery_packaging_spec_is_registered():
    from backend.deployment.windows_contract import (
        PACKAGING_SPEC_FILES,
        REQUIRED_DEPLOYMENT_FILES,
    )

    assert (
        "backend/deployment/AegisGuardRecovery.spec"
        in PACKAGING_SPEC_FILES
    )

    assert (
        "backend/deployment/recovery_cli.py"
        in REQUIRED_DEPLOYMENT_FILES
    )

    assert (
        ROOT
        / "backend/deployment/AegisGuardRecovery.spec"
    ).is_file()

    assert (
        ROOT
        / "backend/deployment/recovery_cli.py"
    ).is_file()


def test_s14_recovery_spec_does_not_bundle_runtime_state_or_tls_material():
    from backend.deployment.windows_contract import (
        find_forbidden_packaging_literals,
    )

    source = (
        ROOT
        / "backend/deployment/AegisGuardRecovery.spec"
    ).read_text(
        encoding="utf-8-sig"
    )

    assert (
        find_forbidden_packaging_literals(
            source
        )
        == []
    )
