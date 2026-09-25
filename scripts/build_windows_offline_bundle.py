"""Build the source-free AegisGuard Windows enterprise bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

BUNDLE_NAME = "AegisGuard-Windows-Enterprise"


BUNDLE_PAYLOAD = (
    (
        "bin/AegisGuardAnalyzer.exe",
        "dist/AegisGuardAnalyzer.exe",
    ),
    (
        "bin/AegisGuardAnalyzerMTLS.exe",
        "dist/AegisGuardAnalyzerMTLS.exe",
    ),
    (
        "bin/AegisGuardCollector.exe",
        "dist/AegisGuardCollector.exe",
    ),
    (
        "bin/AegisGuardRecovery.exe",
        "dist/AegisGuardRecovery.exe",
    ),
    (
        "bin/AegisGuardUserAdmin.exe",
        "dist/AegisGuardUserAdmin.exe",
    ),
    (
        "install_collector.ps1",
        "install_collector.ps1",
    ),
    (
        "deploy/windows/install_analyzer_ui.ps1",
        "deploy/windows/install_analyzer_ui.ps1",
    ),
    (
        "deploy/windows/run_analyzer_ui.ps1",
        "deploy/windows/run_analyzer_ui.ps1",
    ),
    (
        "deploy/windows/install_analyzer_mtls.ps1",
        "deploy/windows/install_analyzer_mtls.ps1",
    ),
    (
        "deploy/windows/run_analyzer_mtls.ps1",
        "deploy/windows/run_analyzer_mtls.ps1",
    ),
    (
        "deploy/windows/run_collector.ps1",
        "deploy/windows/run_collector.ps1",
    ),
    (
        "deploy/windows/configure_collector_mtls.ps1",
        "deploy/windows/configure_collector_mtls.ps1",
    ),
    (
        "deploy/windows/upgrade_enterprise.ps1",
        "deploy/windows/upgrade_enterprise.ps1",
    ),
    (
        "deploy/windows/rollback_enterprise.ps1",
        "deploy/windows/rollback_enterprise.ps1",
    ),
    (
        "BUILD-README.txt",
        "BUILD-README.txt",
    ),
)


FORBIDDEN_SUFFIXES = {
    ".key",
    ".pem",
    ".pfx",
    ".p12",
    ".crt",
    ".cer",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".py",
    ".pyc",
    ".spec",
}


FORBIDDEN_NAMES = {
    "config.json",
    "collector_state.db",
    "aegisguard.db",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest().upper()


def repository_state(root: Path):
    commit = subprocess.run(
        [
            "git",
            "rev-parse",
            "HEAD",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    status = subprocess.run(
        [
            "git",
            "status",
            "--porcelain",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    return commit, bool(status)


def validate_staging(staging: Path):
    issues = []

    for path in staging.rglob("*"):
        if not path.is_file():
            continue

        name = path.name.lower()
        suffix = path.suffix.lower()

        if (
            name in FORBIDDEN_NAMES
            or suffix in FORBIDDEN_SUFFIXES
        ):
            issues.append(
                str(path.relative_to(staging))
            )

    if issues:
        raise RuntimeError(
            "Forbidden material in offline bundle: "
            + ", ".join(sorted(issues))
        )


def build_bundle(
    *,
    root: Path,
    output_dir: Path,
    allow_dirty: bool = False,
):
    root = root.resolve()
    output_dir = output_dir.resolve()

    commit, dirty = repository_state(root)

    if dirty and not allow_dirty:
        raise RuntimeError(
            "Repository working tree is not clean. "
            "Commit validated source before building "
            "the release bundle, or use --allow-dirty "
            "for validation only."
        )

    staging = output_dir / BUNDLE_NAME
    archive = output_dir / f"{BUNDLE_NAME}.zip"

    if staging.exists():
        shutil.rmtree(staging)

    if archive.exists():
        archive.unlink()

    staging.mkdir(
        parents=True,
        exist_ok=True,
    )

    for destination, source in BUNDLE_PAYLOAD:
        source_path = root / source

        if not source_path.is_file():
            raise FileNotFoundError(
                f"Required bundle artifact missing: {source}"
            )

        destination_path = (
            staging
            / Path(destination)
        )

        destination_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copy2(
            source_path,
            destination_path,
        )

    validate_staging(staging)

    entries = []

    for path in sorted(
        staging.rglob("*")
    ):
        if not path.is_file():
            continue

        relative = (
            path.relative_to(staging)
            .as_posix()
        )

        entries.append({
            "path": relative,
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        })

    manifest = {
        "schema_version": 1,
        "product": "AegisGuard Enterprise",
        "platform": "Windows x86_64",
        "bundle": BUNDLE_NAME,
        "source_commit": commit,
        "source_dirty": dirty,
        "payload_files": entries,
        "security": {
            "contains_runtime_database": False,
            "contains_private_keys": False,
            "contains_certificates": False,
            "contains_customer_logs": False,
            "contains_python_source": False,
        },
    }

    manifest_path = (
        staging
        / "manifest.json"
    )

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    checksummed = [
        path
        for path in sorted(
            staging.rglob("*")
        )
        if (
            path.is_file()
            and path.name
            != "SHA256SUMS.txt"
        )
    ]

    checksum_path = (
        staging
        / "SHA256SUMS.txt"
    )

    checksum_path.write_text(
        "".join(
            f"{sha256_file(path)}  "
            f"{path.relative_to(staging).as_posix()}\n"
            for path in checksummed
        ),
        encoding="utf-8",
    )

    validate_staging(staging)

    with zipfile.ZipFile(
        archive,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as bundle:
        for path in sorted(
            staging.rglob("*")
        ):
            if not path.is_file():
                continue

            bundle.write(
                path,
                (
                    Path(BUNDLE_NAME)
                    / path.relative_to(staging)
                ).as_posix(),
            )

    print(
        f"BUNDLE_DIRECTORY = {staging}"
    )
    print(
        f"BUNDLE_ARCHIVE = {archive}"
    )
    print(
        f"SOURCE_COMMIT = {commit}"
    )
    print(
        f"SOURCE_DIRTY = {dirty}"
    )
    print(
        f"PAYLOAD_FILE_COUNT = {len(entries)}"
    )
    print(
        f"ARCHIVE_SHA256 = {sha256_file(archive)}"
    )

    return {
        "directory": staging,
        "archive": archive,
        "manifest": manifest,
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--output-dir",
        default="release",
    )

    parser.add_argument(
        "--allow-dirty",
        action="store_true",
    )

    args = parser.parse_args()

    build_bundle(
        root=ROOT,
        output_dir=(
            ROOT
            / args.output_dir
        ),
        allow_dirty=args.allow_dirty,
    )


if __name__ == "__main__":
    main()
