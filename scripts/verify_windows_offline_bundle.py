"""Verify an AegisGuard Windows enterprise offline bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath


BUNDLE_NAME = "AegisGuard-Windows-Enterprise"
CHECKSUM_FILE = "SHA256SUMS.txt"
MANIFEST_FILE = "manifest.json"

_CHECKSUM_LINE = re.compile(
    r"^([0-9A-Fa-f]{64})  (.+)$"
)

_REQUIRED_SECURITY_FLAGS = {
    "contains_runtime_database": False,
    "contains_private_keys": False,
    "contains_certificates": False,
    "contains_customer_logs": False,
    "contains_python_source": False,
}


class BundleVerificationError(RuntimeError):
    """Raised when an offline release bundle fails verification."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for block in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(block)

    return digest.hexdigest().upper()


def _safe_relative_path(value: str) -> str:
    raw = str(value or "").strip()

    if not raw:
        raise BundleVerificationError(
            "Bundle metadata contains an empty path."
        )

    if "\\" in raw:
        raise BundleVerificationError(
            f"Bundle path must use POSIX separators: {raw}"
        )

    path = PurePosixPath(raw)

    if (
        path.is_absolute()
        or ".." in path.parts
        or "." in path.parts
    ):
        raise BundleVerificationError(
            f"Unsafe bundle path: {raw}"
        )

    normalized = path.as_posix()

    if normalized != raw:
        raise BundleVerificationError(
            f"Non-canonical bundle path: {raw}"
        )

    return normalized


def _parse_checksums(text: str) -> dict[str, str]:
    entries: dict[str, str] = {}

    for line_number, raw_line in enumerate(
        text.splitlines(),
        start=1,
    ):
        line = raw_line.rstrip("\r\n")

        if not line:
            continue

        match = _CHECKSUM_LINE.fullmatch(line)

        if match is None:
            raise BundleVerificationError(
                f"Invalid checksum line {line_number}."
            )

        digest = match.group(1).upper()
        relative = _safe_relative_path(
            match.group(2)
        )

        if relative == CHECKSUM_FILE:
            raise BundleVerificationError(
                "Checksum file must not checksum itself."
            )

        if relative in entries:
            raise BundleVerificationError(
                f"Duplicate checksum path: {relative}"
            )

        entries[relative] = digest

    if not entries:
        raise BundleVerificationError(
            "Checksum file contains no entries."
        )

    return entries


def _validate_manifest(
    manifest: object,
    *,
    allow_dirty_source: bool,
) -> list[dict[str, object]]:
    if not isinstance(manifest, dict):
        raise BundleVerificationError(
            "Manifest must be a JSON object."
        )

    if manifest.get("schema_version") != 1:
        raise BundleVerificationError(
            "Unsupported manifest schema version."
        )

    if manifest.get("product") != "AegisGuard Enterprise":
        raise BundleVerificationError(
            "Unexpected manifest product."
        )

    if manifest.get("platform") != "Windows x86_64":
        raise BundleVerificationError(
            "Unexpected manifest platform."
        )

    if manifest.get("bundle") != BUNDLE_NAME:
        raise BundleVerificationError(
            "Unexpected manifest bundle name."
        )

    source_commit = manifest.get("source_commit")

    if (
        not isinstance(source_commit, str)
        or not re.fullmatch(
            r"[0-9A-Fa-f]{40}",
            source_commit,
        )
    ):
        raise BundleVerificationError(
            "Manifest source_commit must be a 40-character Git SHA."
        )

    source_dirty = manifest.get("source_dirty")

    if not isinstance(source_dirty, bool):
        raise BundleVerificationError(
            "Manifest source_dirty must be boolean."
        )

    if source_dirty and not allow_dirty_source:
        raise BundleVerificationError(
            "Bundle was built from a dirty source tree."
        )

    security = manifest.get("security")

    if not isinstance(security, dict):
        raise BundleVerificationError(
            "Manifest security section is missing."
        )

    for key, expected in _REQUIRED_SECURITY_FLAGS.items():
        if security.get(key) is not expected:
            raise BundleVerificationError(
                f"Manifest security flag is not safe: {key}"
            )

    payload = manifest.get("payload_files")

    if not isinstance(payload, list) or not payload:
        raise BundleVerificationError(
            "Manifest payload_files must be a non-empty list."
        )

    return payload


def _collect_actual_files(root: Path) -> set[str]:
    files: set[str] = set()

    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise BundleVerificationError(
                f"Symlink is not allowed in bundle: "
                f"{path.relative_to(root).as_posix()}"
            )

        if not path.is_file():
            continue

        relative = path.relative_to(root).as_posix()
        relative = _safe_relative_path(relative)

        if relative != CHECKSUM_FILE:
            files.add(relative)

    return files


def verify_bundle_directory(
    root: Path,
    *,
    allow_dirty_source: bool = False,
) -> dict[str, object]:
    root = Path(root).resolve()

    if not root.is_dir():
        raise BundleVerificationError(
            f"Bundle directory does not exist: {root}"
        )

    if root.name != BUNDLE_NAME:
        candidate = root / BUNDLE_NAME

        if candidate.is_dir():
            root = candidate.resolve()
        else:
            raise BundleVerificationError(
                f"Bundle root must be named {BUNDLE_NAME}."
            )

    manifest_path = root / MANIFEST_FILE
    checksum_path = root / CHECKSUM_FILE

    if not manifest_path.is_file():
        raise BundleVerificationError(
            "Bundle manifest.json is missing."
        )

    if not checksum_path.is_file():
        raise BundleVerificationError(
            "Bundle SHA256SUMS.txt is missing."
        )

    try:
        manifest = json.loads(
            manifest_path.read_text(
                encoding="utf-8"
            )
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleVerificationError(
            "Bundle manifest.json is invalid."
        ) from exc

    payload = _validate_manifest(
        manifest,
        allow_dirty_source=allow_dirty_source,
    )

    try:
        checksums = _parse_checksums(
            checksum_path.read_text(
                encoding="utf-8"
            )
        )
    except UnicodeDecodeError as exc:
        raise BundleVerificationError(
            "Bundle SHA256SUMS.txt is not valid UTF-8."
        ) from exc

    actual_files = _collect_actual_files(root)

    if set(checksums) != actual_files:
        missing = sorted(
            actual_files - set(checksums)
        )
        unexpected = sorted(
            set(checksums) - actual_files
        )

        raise BundleVerificationError(
            "Checksum coverage mismatch"
            f"; unlisted_files={missing}"
            f"; missing_files={unexpected}"
        )

    for relative, expected_digest in checksums.items():
        actual_digest = sha256_file(
            root / Path(relative)
        )

        if actual_digest != expected_digest:
            raise BundleVerificationError(
                f"Checksum mismatch: {relative}"
            )

    payload_paths: set[str] = set()

    for index, entry in enumerate(payload):
        if not isinstance(entry, dict):
            raise BundleVerificationError(
                f"Manifest payload entry {index} is invalid."
            )

        relative = _safe_relative_path(
            entry.get("path")
        )

        if relative in payload_paths:
            raise BundleVerificationError(
                f"Duplicate manifest payload path: {relative}"
            )

        if relative in {
            MANIFEST_FILE,
            CHECKSUM_FILE,
        }:
            raise BundleVerificationError(
                f"Reserved file cannot be payload: {relative}"
            )

        payload_paths.add(relative)

        path = root / Path(relative)

        if not path.is_file():
            raise BundleVerificationError(
                f"Manifest payload file is missing: {relative}"
            )

        size = entry.get("size")

        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise BundleVerificationError(
                f"Invalid manifest size: {relative}"
            )

        if path.stat().st_size != size:
            raise BundleVerificationError(
                f"Manifest size mismatch: {relative}"
            )

        digest = entry.get("sha256")

        if (
            not isinstance(digest, str)
            or not re.fullmatch(
                r"[0-9A-Fa-f]{64}",
                digest,
            )
        ):
            raise BundleVerificationError(
                f"Invalid manifest SHA-256: {relative}"
            )

        if sha256_file(path) != digest.upper():
            raise BundleVerificationError(
                f"Manifest SHA-256 mismatch: {relative}"
            )

    expected_payload = (
        actual_files - {MANIFEST_FILE}
    )

    if payload_paths != expected_payload:
        missing = sorted(
            expected_payload - payload_paths
        )
        unexpected = sorted(
            payload_paths - expected_payload
        )

        raise BundleVerificationError(
            "Manifest payload coverage mismatch"
            f"; unlisted_files={missing}"
            f"; missing_files={unexpected}"
        )

    return {
        "status": "PASS",
        "bundle": BUNDLE_NAME,
        "source_commit": manifest["source_commit"],
        "source_dirty": manifest["source_dirty"],
        "payload_file_count": len(payload_paths),
        "checksummed_file_count": len(checksums),
    }


def _zip_entry_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0xFFFF

    return stat.S_IFMT(mode) == stat.S_IFLNK


@contextmanager
def _verified_zip_extraction(archive: Path):
    archive = Path(archive).resolve()

    if not archive.is_file():
        raise BundleVerificationError(
            f"Bundle archive does not exist: {archive}"
        )

    if not zipfile.is_zipfile(archive):
        raise BundleVerificationError(
            "Bundle archive is not a valid ZIP file."
        )

    temp_dir = Path(
        tempfile.mkdtemp(
            prefix="aegisguard-bundle-verify-"
        )
    )

    try:
        seen: set[str] = set()

        with zipfile.ZipFile(archive, "r") as bundle:
            for info in bundle.infolist():
                name = str(info.filename)

                if "\\" in name:
                    raise BundleVerificationError(
                        f"ZIP entry uses unsafe separators: {name}"
                    )

                path = PurePosixPath(name)

                if (
                    path.is_absolute()
                    or ".." in path.parts
                ):
                    raise BundleVerificationError(
                        f"Unsafe ZIP entry path: {name}"
                    )

                if not path.parts:
                    continue

                if path.parts[0] != BUNDLE_NAME:
                    raise BundleVerificationError(
                        f"Unexpected ZIP top-level entry: {name}"
                    )

                if _zip_entry_is_symlink(info):
                    raise BundleVerificationError(
                        f"ZIP symlink is not allowed: {name}"
                    )

                normalized = path.as_posix()

                if normalized in seen:
                    raise BundleVerificationError(
                        f"Duplicate ZIP entry: {normalized}"
                    )

                seen.add(normalized)

                if info.is_dir():
                    continue

                target = temp_dir.joinpath(
                    *path.parts
                )
                target.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                with bundle.open(info, "r") as source:
                    with target.open("wb") as destination:
                        shutil.copyfileobj(
                            source,
                            destination,
                        )

        root = temp_dir / BUNDLE_NAME

        if not root.is_dir():
            raise BundleVerificationError(
                "Bundle root directory is missing."
            )

        yield root

    finally:
        shutil.rmtree(
            temp_dir,
            ignore_errors=True,
        )


def verify_bundle(
    path: Path,
    *,
    allow_dirty_source: bool = False,
) -> dict[str, object]:
    path = Path(path)

    if path.is_dir():
        result = verify_bundle_directory(
            path,
            allow_dirty_source=allow_dirty_source,
        )
        result["archive_sha256"] = None
        return result

    archive_sha256 = sha256_file(path)

    with _verified_zip_extraction(path) as root:
        result = verify_bundle_directory(
            root,
            allow_dirty_source=allow_dirty_source,
        )

    result["archive_sha256"] = archive_sha256
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the integrity and manifest contract of an "
            "AegisGuard Windows enterprise offline bundle."
        )
    )

    parser.add_argument(
        "bundle",
        help=(
            "Path to AegisGuard-Windows-Enterprise.zip, "
            "the extracted bundle directory, or its parent."
        ),
    )

    parser.add_argument(
        "--allow-dirty-source",
        action="store_true",
        help=(
            "Permit bundles whose manifest records source_dirty=true. "
            "Do not use this for production release acceptance."
        ),
    )

    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
    )

    args = parser.parse_args(argv)

    try:
        result = verify_bundle(
            Path(args.bundle),
            allow_dirty_source=args.allow_dirty_source,
        )
    except (
        OSError,
        BundleVerificationError,
        zipfile.BadZipFile,
    ) as exc:
        if args.json_output:
            print(
                json.dumps({
                    "status": "FAIL",
                    "error": str(exc),
                })
            )
        else:
            print(
                f"BUNDLE_VERIFICATION = FAIL\nERROR = {exc}",
                file=sys.stderr,
            )
        return 1

    if args.json_output:
        print(
            json.dumps(
                result,
                sort_keys=True,
            )
        )
    else:
        print("BUNDLE_VERIFICATION = PASS")
        print(
            f"SOURCE_COMMIT = {result['source_commit']}"
        )
        print(
            f"SOURCE_DIRTY = {result['source_dirty']}"
        )
        print(
            "PAYLOAD_FILE_COUNT = "
            f"{result['payload_file_count']}"
        )
        print(
            "CHECKSUMMED_FILE_COUNT = "
            f"{result['checksummed_file_count']}"
        )

        if result["archive_sha256"]:
            print(
                "ARCHIVE_SHA256 = "
                f"{result['archive_sha256']}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
