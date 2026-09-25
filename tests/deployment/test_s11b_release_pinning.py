import importlib.util
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


def _build_bundle(tmp_path, monkeypatch):
    builder = _load(
        BUILDER_PATH,
        "s11b_builder",
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
                b"MZ-AegisGuard-S11B-test-binary"
            )
        else:
            path.write_text(
                f"test:{relative}\n",
                encoding="utf-8",
            )

    monkeypatch.setattr(
        builder,
        "repository_state",
        lambda _root: ("b" * 40, False),
    )

    return builder.build_bundle(
        root=source,
        output_dir=output,
    )


def test_valid_archive_and_commit_pins_are_accepted(
    tmp_path,
    monkeypatch,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11b_verifier_valid",
    )

    built = _build_bundle(
        tmp_path,
        monkeypatch,
    )

    archive_sha = verifier.sha256_file(
        built["archive"]
    )

    result = verifier.verify_bundle(
        built["archive"],
        expected_archive_sha256=archive_sha,
        expected_source_commit="b" * 40,
    )

    assert result["status"] == "PASS"
    assert result["archive_pin_verified"] is True
    assert result["source_commit_pin_verified"] is True


def test_wrong_archive_pin_fails_closed(
    tmp_path,
    monkeypatch,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11b_verifier_bad_archive",
    )

    built = _build_bundle(
        tmp_path,
        monkeypatch,
    )

    with pytest.raises(
        verifier.BundleVerificationError,
        match="trusted release pin",
    ):
        verifier.verify_bundle(
            built["archive"],
            expected_archive_sha256="0" * 64,
        )


def test_wrong_source_commit_pin_fails_closed(
    tmp_path,
    monkeypatch,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11b_verifier_bad_commit",
    )

    built = _build_bundle(
        tmp_path,
        monkeypatch,
    )

    with pytest.raises(
        verifier.BundleVerificationError,
        match="source commit.*trusted release pin",
    ):
        verifier.verify_bundle(
            built["archive"],
            expected_source_commit="c" * 40,
        )


def test_invalid_pin_formats_are_rejected(
    tmp_path,
    monkeypatch,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11b_verifier_bad_format",
    )

    built = _build_bundle(
        tmp_path,
        monkeypatch,
    )

    with pytest.raises(
        verifier.BundleVerificationError,
        match="64-character SHA-256",
    ):
        verifier.verify_bundle(
            built["archive"],
            expected_archive_sha256="not-a-sha256",
        )

    with pytest.raises(
        verifier.BundleVerificationError,
        match="40-character Git commit SHA",
    ):
        verifier.verify_bundle(
            built["archive"],
            expected_source_commit="not-a-commit",
        )


def test_archive_pin_requires_zip_input(
    tmp_path,
    monkeypatch,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11b_verifier_directory",
    )

    built = _build_bundle(
        tmp_path,
        monkeypatch,
    )

    with pytest.raises(
        verifier.BundleVerificationError,
        match="requires ZIP archive verification",
    ):
        verifier.verify_bundle(
            built["directory"],
            expected_archive_sha256="0" * 64,
        )


def test_pinning_is_optional_for_s11a_compatibility(
    tmp_path,
    monkeypatch,
):
    verifier = _load(
        VERIFIER_PATH,
        "s11b_verifier_compatibility",
    )

    built = _build_bundle(
        tmp_path,
        monkeypatch,
    )

    result = verifier.verify_bundle(
        built["archive"]
    )

    assert result["status"] == "PASS"
    assert result["archive_pin_verified"] is False
    assert result["source_commit_pin_verified"] is False
