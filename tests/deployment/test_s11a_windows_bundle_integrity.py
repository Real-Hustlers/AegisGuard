import importlib.util
import json
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]

BUILDER_PATH = (
    ROOT
    / "scripts"
    / "build_windows_offline_bundle.py"
)

VERIFIER_PATH = (
    ROOT
    / "scripts"
    / "verify_windows_offline_bundle.py"
)


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(
        name,
        path,
    )
    module = importlib.util.module_from_spec(
        spec
    )
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _build_bundle(tmp_path, monkeypatch, *, dirty=False):
    builder = _load(
        BUILDER_PATH,
        "s11a_builder",
    )

    source = tmp_path / "source"
    output = tmp_path / "output"
    source.mkdir()

    for destination, relative in builder.BUNDLE_PAYLOAD:
        path = source / relative
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        if destination.endswith(".exe"):
            path.write_bytes(
                b"MZ-AegisGuard-S11A-test-binary"
            )
        else:
            path.write_text(
                f"test:{relative}\n",
                encoding="utf-8",
            )

    monkeypatch.setattr(
        builder,
        "repository_state",
        lambda _root: ("a" * 40, dirty),
    )

    return builder.build_bundle(
        root=source,
        output_dir=output,
        allow_dirty=dirty,
    )


def test_verifier_accepts_existing_s10e_builder_output(
    tmp_path,
    monkeypatch,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11a_verifier_valid",
    )

    built = _build_bundle(
        tmp_path,
        monkeypatch,
    )

    result = verifier.verify_bundle(
        built["archive"]
    )

    assert result["status"] == "PASS"
    assert result["source_commit"] == "a" * 40
    assert result["source_dirty"] is False
    assert result["payload_file_count"] == len(
        built["manifest"]["payload_files"]
    )
    assert len(result["archive_sha256"]) == 64


def test_verifier_rejects_payload_tampering(
    tmp_path,
    monkeypatch,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11a_verifier_tamper",
    )

    built = _build_bundle(
        tmp_path,
        monkeypatch,
    )

    target = (
        built["directory"]
        / "bin"
        / "AegisGuardAnalyzer.exe"
    )

    target.write_bytes(
        b"tampered-binary"
    )

    with pytest.raises(
        verifier.BundleVerificationError,
        match="Checksum mismatch",
    ):
        verifier.verify_bundle_directory(
            built["directory"]
        )


def test_verifier_rejects_unlisted_extra_file(
    tmp_path,
    monkeypatch,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11a_verifier_extra",
    )

    built = _build_bundle(
        tmp_path,
        monkeypatch,
    )

    (
        built["directory"]
        / "unexpected.txt"
    ).write_text(
        "unexpected",
        encoding="utf-8",
    )

    with pytest.raises(
        verifier.BundleVerificationError,
        match="Checksum coverage mismatch",
    ):
        verifier.verify_bundle_directory(
            built["directory"]
        )


def test_verifier_rejects_dirty_source_release_by_default(
    tmp_path,
    monkeypatch,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11a_verifier_dirty",
    )

    built = _build_bundle(
        tmp_path,
        monkeypatch,
        dirty=True,
    )

    with pytest.raises(
        verifier.BundleVerificationError,
        match="dirty source tree",
    ):
        verifier.verify_bundle(
            built["archive"]
        )

    accepted = verifier.verify_bundle(
        built["archive"],
        allow_dirty_source=True,
    )

    assert accepted["status"] == "PASS"
    assert accepted["source_dirty"] is True


def test_verifier_rejects_unsafe_checksum_path(
    tmp_path,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11a_verifier_unsafe",
    )

    root = (
        tmp_path
        / verifier.BUNDLE_NAME
    )
    root.mkdir()

    (root / "manifest.json").write_text(
        json.dumps({
            "schema_version": 1,
            "product": "AegisGuard Enterprise",
            "platform": "Windows x86_64",
            "bundle": verifier.BUNDLE_NAME,
            "source_commit": "a" * 40,
            "source_dirty": False,
            "payload_files": [{
                "path": "payload.bin",
                "size": 1,
                "sha256": "0" * 64,
            }],
            "security": {
                "contains_runtime_database": False,
                "contains_private_keys": False,
                "contains_certificates": False,
                "contains_customer_logs": False,
                "contains_python_source": False,
            },
        }),
        encoding="utf-8",
    )

    (root / "payload.bin").write_bytes(
        b"x"
    )

    (root / "SHA256SUMS.txt").write_text(
        ("0" * 64)
        + "  ../outside.bin\n",
        encoding="utf-8",
    )

    with pytest.raises(
        verifier.BundleVerificationError,
        match="Unsafe bundle path",
    ):
        verifier.verify_bundle_directory(root)


def test_verifier_rejects_zip_path_traversal(
    tmp_path,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11a_verifier_zip_traversal",
    )

    archive = tmp_path / "unsafe.zip"

    with zipfile.ZipFile(
        archive,
        "w",
    ) as bundle:
        bundle.writestr(
            f"{verifier.BUNDLE_NAME}/../escape.txt",
            b"escape",
        )

    with pytest.raises(
        verifier.BundleVerificationError,
        match="Unsafe ZIP entry path",
    ):
        verifier.verify_bundle(archive)
