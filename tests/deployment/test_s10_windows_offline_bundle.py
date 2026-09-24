import importlib.util
import json
import subprocess
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]

SCRIPT = (
    ROOT
    / "scripts"
    / "build_windows_offline_bundle.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "s10_windows_bundle",
        SCRIPT,
    )

    module = importlib.util.module_from_spec(
        spec
    )

    assert spec.loader is not None

    spec.loader.exec_module(module)

    return module


def test_offline_bundle_payload_is_source_free():
    module = _load_module()

    destinations = {
        destination
        for destination, _source
        in module.BUNDLE_PAYLOAD
    }

    assert {
        "bin/AegisGuardAnalyzer.exe",
        "bin/AegisGuardAnalyzerMTLS.exe",
        "bin/AegisGuardCollector.exe",
    }.issubset(destinations)

    forbidden = (
        ".py",
        ".pyc",
        ".spec",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".key",
        ".pem",
        ".pfx",
        ".p12",
        ".crt",
        ".cer",
    )

    for destination in destinations:
        assert not destination.lower().endswith(
            forbidden
        )


def test_offline_bundle_contains_required_installers():
    module = _load_module()

    destinations = {
        destination
        for destination, _source
        in module.BUNDLE_PAYLOAD
    }

    for required in (
        "install_collector.ps1",
        "deploy/windows/install_analyzer_ui.ps1",
        "deploy/windows/run_analyzer_ui.ps1",
        "deploy/windows/install_analyzer_mtls.ps1",
        "deploy/windows/run_analyzer_mtls.ps1",
        "deploy/windows/run_collector.ps1",
        "deploy/windows/configure_collector_mtls.ps1",
        "BUILD-README.txt",
    ):
        assert required in destinations


def test_staging_validation_rejects_sensitive_material(
    tmp_path,
):
    module = _load_module()

    forbidden = (
        tmp_path
        / "server.key"
    )

    forbidden.write_text(
        "validation-secret",
        encoding="utf-8",
    )

    with pytest.raises(
        RuntimeError,
        match="Forbidden material",
    ):
        module.validate_staging(
            tmp_path
        )


def test_bundle_builder_creates_manifest_and_checksums(
    tmp_path,
    monkeypatch,
):
    module = _load_module()

    source = (
        tmp_path
        / "source"
    )

    output = (
        tmp_path
        / "output"
    )

    source.mkdir()

    for destination, relative in module.BUNDLE_PAYLOAD:
        path = source / relative
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if destination.endswith(".exe"):
            path.write_bytes(
                b"MZ-S10E-validation-binary"
            )
        else:
            path.write_text(
                f"validation:{relative}\n",
                encoding="utf-8",
            )

    def fake_repository_state(_root):
        return (
            "a" * 40,
            False,
        )

    monkeypatch.setattr(
        module,
        "repository_state",
        fake_repository_state,
    )

    result = module.build_bundle(
        root=source,
        output_dir=output,
    )

    staging = result["directory"]
    archive = result["archive"]

    assert archive.is_file()

    manifest = json.loads(
        (
            staging
            / "manifest.json"
        ).read_text(
            encoding="utf-8"
        )
    )

    assert (
        manifest["source_commit"]
        == "a" * 40
    )

    assert (
        manifest["source_dirty"]
        is False
    )

    assert (
        manifest["security"][
            "contains_private_keys"
        ]
        is False
    )

    assert (
        staging
        / "SHA256SUMS.txt"
    ).is_file()

    with zipfile.ZipFile(
        archive,
        "r",
    ) as bundle:
        names = set(
            bundle.namelist()
        )

    assert (
        "AegisGuard-Windows-Enterprise/"
        "manifest.json"
        in names
    )

    assert not any(
        name.endswith(".py")
        for name in names
    )
