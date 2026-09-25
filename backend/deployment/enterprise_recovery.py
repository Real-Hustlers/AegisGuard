"""Verified AegisGuard Enterprise backup and recovery primitives."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from backend.storage.audit_integrity import verify_audit_chain


BACKUP_SCHEMA_VERSION = 1
BACKUP_PRODUCT = "AegisGuard Enterprise"
BACKUP_KIND = "enterprise-state"

REQUIRED_ANALYZER_TABLES = frozenset({
    "security_logs",
    "incidents",
    "response_actions",
    "collectors",
    "collector_ingest_batches",
    "audit_events",
    "users",
    "sessions",
    "platform_schema_migrations",
})

TRANSIENT_ANALYZER_TABLES = (
    "sessions",
    "auth_login_throttle",
)

COLLECTOR_STATE_ALLOWLIST = frozenset({
    "collector_id",
    "last_acked_record_id",
    "last_successful_ack_at",
    "collector_active_client_certificate_ref_v1",
})

COLLECTOR_CONFIG_ALLOWLIST = frozenset({
    "log_name",
    "analyzer_url",
    "collector_ingest_url",
    "collector_enrollment_url",
    "collector_heartbeat_url",
    "collector_heartbeat_interval_seconds",
    "collector_rotation_url",
    "collector_recovery_url",
    "collector_certificate_rotation_url",
    "collector_mtls_required",
    "collector_client_certificate",
    "collector_client_key",
    "collector_auth_required",
    "collector_version",
    "collector_state_file",
    "ca_bundle",
    "collector_retry_base_seconds",
    "collector_retry_max_seconds",
    "collector_retry_jitter_ratio",
    "event_ids",
    "max_events",
    "hours",
    "raw_output_enabled",
    "raw_output_file",
})

FORBIDDEN_CONFIG_KEYS = frozenset({
    "enrollment_token",
    "recovery_token",
    "collector_credential",
    "password",
    "private_key",
    "session_token",
    "access_token",
    "refresh_token",
    "api_key",
})

ML_ALLOWED_FILENAMES = frozenset({
    "metadata.json",
    "active.json",
    "model.joblib",
    "encoder.joblib",
})

FORBIDDEN_ARCHIVE_SUFFIXES = frozenset({
    ".key",
    ".pem",
    ".pfx",
    ".p12",
    ".crt",
    ".cer",
})

PAYLOAD_ANALYZER_DB = "payload/analyzer/aegisguard.db"
PAYLOAD_COLLECTOR_CONFIG = "payload/collector/config.json"
PAYLOAD_COLLECTOR_STATE = "payload/collector/collector_state.db"
PAYLOAD_ML_PREFIX = "payload/ml_registry/"


class RecoveryError(RuntimeError):
    """Base backup/recovery failure."""


class BackupIntegrityError(RecoveryError):
    """Raised when backup evidence is missing, corrupt, or inconsistent."""


class RestoreSafetyError(RecoveryError):
    """Raised when an unsafe restore is requested."""


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            digest.update(block)
    return digest.hexdigest().upper()


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def _atomic_json_write(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(
        target.name + ".tmp-" + uuid.uuid4().hex
    )
    temporary.write_bytes(
        _canonical_json_bytes(value)
    )
    os.replace(temporary, target)


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type='table'
            """
        ).fetchall()
    }


def _quick_check(conn: sqlite3.Connection) -> None:
    row = conn.execute(
        "PRAGMA quick_check(1)"
    ).fetchone()
    if (
        row is None
        or str(row[0]).strip().lower() != "ok"
    ):
        raise BackupIntegrityError(
            "SQLite quick_check failed"
        )


def _count(conn: sqlite3.Connection, table: str) -> int:
    return int(
        conn.execute(
            f'SELECT COUNT(*) FROM "{table}"'
        ).fetchone()[0]
    )


def _response_status_counts(
    conn: sqlite3.Connection,
) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT COALESCE(status, '') AS status,
               COUNT(*)
        FROM response_actions
        GROUP BY COALESCE(status, '')
        ORDER BY status
        """
    ).fetchall()
    return {
        str(row[0]): int(row[1])
        for row in rows
    }


def verify_analyzer_database(
    path: str | Path,
    *,
    require_sanitized: bool,
) -> dict[str, Any]:
    database = Path(path)
    if not database.is_file():
        raise BackupIntegrityError(
            f"Analyzer database is missing: {database}"
        )

    conn = sqlite3.connect(str(database))
    try:
        _quick_check(conn)
        tables = _table_names(conn)
        missing = sorted(
            REQUIRED_ANALYZER_TABLES - tables
        )
        if missing:
            raise BackupIntegrityError(
                "Analyzer database is missing required tables: "
                + ", ".join(missing)
            )

        if require_sanitized:
            for table in TRANSIENT_ANALYZER_TABLES:
                if table in tables and _count(conn, table) != 0:
                    raise BackupIntegrityError(
                        f"transient table was not purged: {table}"
                    )

        audit = verify_audit_chain(conn)
        if not audit["valid"]:
            raise BackupIntegrityError(
                "audit chain is invalid: "
                + str(audit["reason"])
            )

        schema_version = int(
            conn.execute(
                """
                SELECT COALESCE(MAX(version), 0)
                FROM platform_schema_migrations
                """
            ).fetchone()[0]
        )

        return {
            "platform_schema_version": schema_version,
            "security_log_count": _count(
                conn,
                "security_logs",
            ),
            "incident_count": _count(
                conn,
                "incidents",
            ),
            "response_action_count": _count(
                conn,
                "response_actions",
            ),
            "response_status_counts": (
                _response_status_counts(conn)
            ),
            "collector_count": _count(
                conn,
                "collectors",
            ),
            "collector_ingest_batch_count": _count(
                conn,
                "collector_ingest_batches",
            ),
            "audit_event_count": int(
                audit["event_count"]
            ),
            "audit_head_hash": str(
                audit["head_hash"]
            ),
            "audit_valid": True,
            "sessions_present": (
                _count(conn, "sessions")
                if "sessions" in tables
                else 0
            ),
        }
    finally:
        conn.close()


def create_sanitized_analyzer_snapshot(
    source: str | Path,
    destination: str | Path,
) -> dict[str, Any]:
    source_path = Path(source)
    destination_path = Path(destination)

    if not source_path.is_file():
        raise FileNotFoundError(
            f"Analyzer database not found: {source_path}"
        )

    destination_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if destination_path.exists():
        destination_path.unlink()

    source_conn = sqlite3.connect(
        str(source_path),
        timeout=30,
    )
    destination_conn = sqlite3.connect(
        str(destination_path),
        timeout=30,
    )

    try:
        source_conn.backup(
            destination_conn
        )
        destination_conn.commit()

        tables = _table_names(
            destination_conn
        )

        destination_conn.execute(
            "PRAGMA secure_delete = ON"
        )
        destination_conn.execute(
            "PRAGMA temp_store = MEMORY"
        )

        for table in TRANSIENT_ANALYZER_TABLES:
            if table in tables:
                destination_conn.execute(
                    f'DELETE FROM "{table}"'
                )

        destination_conn.commit()

        # Compact after transient-state deletion so stale session rows are not
        # retained in free pages inside the portable backup file.
        destination_conn.execute(
            "VACUUM"
        )
        destination_conn.commit()
    finally:
        source_conn.close()
        destination_conn.close()

    return verify_analyzer_database(
        destination_path,
        require_sanitized=True,
    )


def sanitize_collector_config(
    source: str | Path,
    destination: str | Path,
) -> dict[str, Any]:
    source_path = Path(source)
    destination_path = Path(destination)

    payload = json.loads(
        source_path.read_text(
            encoding="utf-8-sig"
        )
    )
    if not isinstance(payload, dict):
        raise BackupIntegrityError(
            "collector config must be a JSON object"
        )

    sanitized = {
        key: payload[key]
        for key in sorted(
            COLLECTOR_CONFIG_ALLOWLIST
        )
        if key in payload
    }

    if (
        set(sanitized)
        & FORBIDDEN_CONFIG_KEYS
    ):
        raise BackupIntegrityError(
            "collector config projection contains a forbidden secret field"
        )

    destination_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    destination_path.write_bytes(
        _canonical_json_bytes(
            sanitized
        )
    )

    return {
        "included_keys": sorted(
            sanitized
        ),
        "omitted_keys": sorted(
            set(payload) - set(sanitized)
        ),
    }


def verify_collector_config(
    path: str | Path,
) -> dict[str, Any]:
    value = json.loads(
        Path(path).read_text(
            encoding="utf-8-sig"
        )
    )

    if not isinstance(value, dict):
        raise BackupIntegrityError(
            "collector config backup must be a JSON object"
        )

    keys = set(value)

    if not keys.issubset(
        COLLECTOR_CONFIG_ALLOWLIST
    ):
        raise BackupIntegrityError(
            "collector config backup contains unapproved keys"
        )

    if keys & FORBIDDEN_CONFIG_KEYS:
        raise BackupIntegrityError(
            "collector config backup contains secret-bearing keys"
        )

    return {
        "included_keys": sorted(keys),
    }


def create_collector_state_projection(
    source: str | Path,
    destination: str | Path,
) -> dict[str, Any]:
    source_path = Path(source)
    destination_path = Path(destination)

    if not source_path.is_file():
        raise FileNotFoundError(
            f"Collector state database not found: {source_path}"
        )

    source_conn = sqlite3.connect(
        str(source_path),
        timeout=30,
    )
    source_conn.row_factory = sqlite3.Row

    try:
        _quick_check(source_conn)
        tables = _table_names(source_conn)
        if "collector_state" not in tables:
            raise BackupIntegrityError(
                "collector state table is missing"
            )

        rows = source_conn.execute(
            """
            SELECT key, value
            FROM collector_state
            ORDER BY key
            """
        ).fetchall()

        projected = {
            str(row["key"]): str(row["value"])
            for row in rows
            if str(row["key"])
            in COLLECTOR_STATE_ALLOWLIST
        }
    finally:
        source_conn.close()

    destination_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if destination_path.exists():
        destination_path.unlink()

    conn = sqlite3.connect(
        str(destination_path)
    )
    try:
        conn.execute(
            "PRAGMA secure_delete = ON"
        )
        conn.executescript(
            """
            CREATE TABLE collector_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE outbound_batches (
                batch_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                max_record_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                last_attempt_at REAL,
                next_attempt_at REAL
            );
            """
        )

        conn.executemany(
            """
            INSERT INTO collector_state(key, value)
            VALUES (?, ?)
            """,
            sorted(projected.items()),
        )
        conn.commit()
    finally:
        conn.close()

    return verify_collector_state_projection(
        destination_path
    )


def verify_collector_state_projection(
    path: str | Path,
) -> dict[str, Any]:
    database = Path(path)
    if not database.is_file():
        raise BackupIntegrityError(
            "collector state projection is missing"
        )

    conn = sqlite3.connect(
        str(database)
    )
    try:
        _quick_check(conn)
        tables = _table_names(conn)

        if not {
            "collector_state",
            "outbound_batches",
        }.issubset(tables):
            raise BackupIntegrityError(
                "collector state projection schema is incomplete"
            )

        rows = conn.execute(
            """
            SELECT key, value
            FROM collector_state
            ORDER BY key
            """
        ).fetchall()

        keys = {
            str(row[0])
            for row in rows
        }

        if not keys.issubset(
            COLLECTOR_STATE_ALLOWLIST
        ):
            raise BackupIntegrityError(
                "collector state projection contains unapproved keys"
            )

        if _count(conn, "outbound_batches") != 0:
            raise BackupIntegrityError(
                "collector state projection contains queued event payloads"
            )

        values = {
            str(row[0]): str(row[1])
            for row in rows
        }

        return {
            "keys": sorted(keys),
            "collector_id": values.get(
                "collector_id"
            ),
            "last_acked_record_id": (
                int(values["last_acked_record_id"])
                if "last_acked_record_id" in values
                else None
            ),
            "outbound_batch_count": 0,
        }
    finally:
        conn.close()


def _copy_ml_registry(
    source: str | Path,
    destination: str | Path,
) -> None:
    source_root = Path(source)
    destination_root = Path(destination)

    if not source_root.exists():
        return

    if not source_root.is_dir():
        raise BackupIntegrityError(
            "ML registry path must be a directory"
        )

    for source_path in sorted(
        source_root.rglob("*")
    ):
        if source_path.is_symlink():
            raise BackupIntegrityError(
                "ML registry symlinks are not allowed"
            )

        if not source_path.is_file():
            continue

        if (
            source_path.name
            not in ML_ALLOWED_FILENAMES
        ):
            continue

        relative = source_path.relative_to(
            source_root
        )

        target = (
            destination_root
            / relative
        )
        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        shutil.copy2(
            source_path,
            target,
        )


def verify_ml_registry(
    root: str | Path,
) -> dict[str, Any]:
    registry = Path(root)

    if not registry.exists():
        return {
            "present": False,
            "model_count": 0,
            "version_count": 0,
            "active_model_count": 0,
        }

    if not registry.is_dir():
        raise BackupIntegrityError(
            "ML registry backup is not a directory"
        )

    files = [
        path
        for path in registry.rglob("*")
        if path.is_file()
    ]

    for path in files:
        if (
            path.name
            not in ML_ALLOWED_FILENAMES
        ):
            raise BackupIntegrityError(
                "ML registry backup contains an unapproved file: "
                + str(
                    path.relative_to(
                        registry
                    )
                )
            )

    metadata_paths = sorted(
        registry.rglob("metadata.json")
    )

    versions: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    for metadata_path in metadata_paths:
        relative = metadata_path.relative_to(
            registry
        )

        if len(relative.parts) != 3:
            raise BackupIntegrityError(
                "ML metadata path is not model/version/metadata.json"
            )

        model_dir = relative.parts[0]
        version_dir = relative.parts[1]

        metadata = json.loads(
            metadata_path.read_text(
                encoding="utf-8"
            )
        )

        if (
            str(metadata.get("model_name") or "")
            != model_dir
        ):
            raise BackupIntegrityError(
                "ML model_name does not match registry path"
            )

        if (
            str(metadata.get("model_version") or "")
            != version_dir
        ):
            raise BackupIntegrityError(
                "ML model_version does not match registry path"
            )

        model_path = (
            metadata_path.parent
            / "model.joblib"
        )
        encoder_path = (
            metadata_path.parent
            / "encoder.joblib"
        )

        if not model_path.is_file():
            raise BackupIntegrityError(
                "ML model artifact is missing"
            )

        if not encoder_path.is_file():
            raise BackupIntegrityError(
                "ML encoder artifact is missing"
            )

        if (
            sha256_file(model_path)
            != str(
                metadata.get(
                    "model_sha256"
                )
                or ""
            ).upper()
        ):
            raise BackupIntegrityError(
                "ML model artifact hash mismatch"
            )

        if (
            sha256_file(encoder_path)
            != str(
                metadata.get(
                    "encoder_sha256"
                )
                or ""
            ).upper()
        ):
            raise BackupIntegrityError(
                "ML encoder artifact hash mismatch"
            )

        versions[
            (
                model_dir,
                version_dir,
            )
        ] = metadata

    active_paths = sorted(
        registry.rglob("active.json")
    )

    active_models = set()

    for active_path in active_paths:
        relative = active_path.relative_to(
            registry
        )

        if len(relative.parts) != 2:
            raise BackupIntegrityError(
                "ML active.json path is not model/active.json"
            )

        model_name = relative.parts[0]
        active = json.loads(
            active_path.read_text(
                encoding="utf-8"
            )
        )

        version = str(
            active.get(
                "model_version"
            )
            or ""
        )

        metadata = versions.get(
            (
                model_name,
                version,
            )
        )

        if metadata is None:
            raise BackupIntegrityError(
                "active ML version metadata is missing"
            )

        if (
            str(
                metadata.get(
                    "stage"
                )
                or ""
            ).upper()
            != "PROMOTED"
        ):
            raise BackupIntegrityError(
                "active ML version is not PROMOTED"
            )

        active_models.add(
            model_name
        )

    return {
        "present": bool(files),
        "model_count": len(
            {
                model
                for model, _version
                in versions
            }
        ),
        "version_count": len(
            versions
        ),
        "active_model_count": len(
            active_models
        ),
    }


def _validate_archive_name(name: str) -> str:
    value = str(name)

    if "\\" in value:
        raise BackupIntegrityError(
            "backup archive paths must use POSIX separators"
        )

    path = PurePosixPath(value)

    if path.is_absolute():
        raise BackupIntegrityError(
            "backup archive contains an absolute path"
        )

    if (
        ".." in path.parts
        or "." in path.parts
    ):
        raise BackupIntegrityError(
            "backup archive contains an unsafe path"
        )

    return value


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (
        info.external_attr
        >> 16
    )
    return (
        stat.S_IFMT(mode)
        == stat.S_IFLNK
    )


def _write_zip_member(
    archive: zipfile.ZipFile,
    name: str,
    data: bytes,
) -> None:
    info = zipfile.ZipInfo(
        filename=name,
        date_time=(
            1980,
            1,
            1,
            0,
            0,
            0,
        ),
    )
    info.compress_type = (
        zipfile.ZIP_DEFLATED
    )
    info.external_attr = (
        0o600
        << 16
    )
    archive.writestr(
        info,
        data,
    )


def _payload_entries(
    root: Path,
) -> list[dict[str, Any]]:
    entries = []

    for path in sorted(
        root.rglob("*")
    ):
        if not path.is_file():
            continue

        relative = (
            path.relative_to(
                root
            )
            .as_posix()
        )

        if (
            Path(relative).suffix.lower()
            in FORBIDDEN_ARCHIVE_SUFFIXES
        ):
            raise BackupIntegrityError(
                "backup payload contains forbidden TLS/private material"
            )

        entries.append({
            "path": relative,
            "size": path.stat().st_size,
            "sha256": sha256_file(
                path
            ),
        })

    return entries


def create_backup(
    *,
    output: str | Path,
    analyzer_db: str | Path,
    collector_config: str | Path | None = None,
    collector_state: str | Path | None = None,
    ml_registry: str | Path | None = None,
) -> dict[str, Any]:
    output_path = Path(output).resolve()

    if output_path.exists():
        raise FileExistsError(
            f"backup already exists: {output_path}"
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        prefix="aegisguard-backup-"
    ) as temporary_name:
        staging = Path(
            temporary_name
        )

        analyzer_target = (
            staging
            / PAYLOAD_ANALYZER_DB
        )

        analyzer_evidence = (
            create_sanitized_analyzer_snapshot(
                analyzer_db,
                analyzer_target,
            )
        )

        components = {
            "analyzer_database": True,
            "collector_config": False,
            "collector_state_projection": False,
            "ml_registry": False,
        }

        collector_config_evidence = None
        collector_state_evidence = None

        if collector_config is not None:
            collector_config_evidence = (
                sanitize_collector_config(
                    collector_config,
                    staging
                    / PAYLOAD_COLLECTOR_CONFIG,
                )
            )
            components[
                "collector_config"
            ] = True

        if collector_state is not None:
            collector_state_evidence = (
                create_collector_state_projection(
                    collector_state,
                    staging
                    / PAYLOAD_COLLECTOR_STATE,
                )
            )
            components[
                "collector_state_projection"
            ] = True

        ml_evidence = {
            "present": False,
            "model_count": 0,
            "version_count": 0,
            "active_model_count": 0,
        }

        if (
            ml_registry is not None
            and Path(
                ml_registry
            ).exists()
        ):
            ml_target = (
                staging
                / "payload"
                / "ml_registry"
            )

            _copy_ml_registry(
                ml_registry,
                ml_target,
            )

            ml_evidence = (
                verify_ml_registry(
                    ml_target
                )
            )

            components[
                "ml_registry"
            ] = bool(
                ml_evidence[
                    "present"
                ]
            )

        entries = _payload_entries(
            staging
        )

        descriptor_digest = hashlib.sha256(
            _canonical_json_bytes(
                entries
            )
        ).hexdigest().upper()

        manifest = {
            "schema_version": (
                BACKUP_SCHEMA_VERSION
            ),
            "product": (
                BACKUP_PRODUCT
            ),
            "backup_kind": (
                BACKUP_KIND
            ),
            "backup_id": (
                "AGB-"
                + descriptor_digest[:20]
            ),
            "created_at_utc": (
                _utc_now()
            ),
            "components": components,
            "files": entries,
            "evidence": {
                "analyzer": (
                    analyzer_evidence
                ),
                "collector_config": (
                    collector_config_evidence
                ),
                "collector_state": (
                    collector_state_evidence
                ),
                "ml_registry": (
                    ml_evidence
                ),
            },
            "security_policy": {
                "transient_sessions_removed": True,
                "login_throttle_removed": True,
                "collector_credentials_excluded": True,
                "collector_pending_rotations_excluded": True,
                "collector_pending_recovery_excluded": True,
                "collector_outbound_event_payloads_excluded": True,
                "tls_private_material_excluded": True,
                "tls_certificate_files_excluded": True,
                "customer_export_artifacts_excluded": True,
                "collector_certificate_path_references_may_be_preserved": True,
            },
        }

        manifest_bytes = (
            _canonical_json_bytes(
                manifest
            )
        )

        with zipfile.ZipFile(
            output_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            _write_zip_member(
                archive,
                "manifest.json",
                manifest_bytes,
            )

            for entry in entries:
                source = (
                    staging
                    / entry["path"]
                )
                _write_zip_member(
                    archive,
                    entry["path"],
                    source.read_bytes(),
                )

    verification = verify_backup(
        output_path
    )

    return {
        "backup": output_path,
        "archive_sha256": sha256_file(
            output_path
        ),
        "manifest": verification[
            "manifest"
        ],
    }


def _extract_and_validate(
    backup: str | Path,
    destination: Path,
) -> dict[str, Any]:
    backup_path = Path(
        backup
    )

    if not backup_path.is_file():
        raise FileNotFoundError(
            f"backup archive not found: {backup_path}"
        )

    with zipfile.ZipFile(
        backup_path,
        "r",
    ) as archive:
        infos = archive.infolist()
        names = [
            _validate_archive_name(
                info.filename
            )
            for info in infos
        ]

        if len(names) != len(
            set(names)
        ):
            raise BackupIntegrityError(
                "backup archive contains duplicate paths"
            )

        for info in infos:
            if _is_symlink(info):
                raise BackupIntegrityError(
                    "backup archive contains a symlink"
                )

        if "manifest.json" not in names:
            raise BackupIntegrityError(
                "backup manifest is missing"
            )

        manifest = json.loads(
            archive.read(
                "manifest.json"
            ).decode(
                "utf-8"
            )
        )

        if (
            manifest.get(
                "schema_version"
            )
            != BACKUP_SCHEMA_VERSION
        ):
            raise BackupIntegrityError(
                "unsupported backup schema version"
            )

        if (
            manifest.get(
                "product"
            )
            != BACKUP_PRODUCT
        ):
            raise BackupIntegrityError(
                "unexpected backup product"
            )

        if (
            manifest.get(
                "backup_kind"
            )
            != BACKUP_KIND
        ):
            raise BackupIntegrityError(
                "unexpected backup kind"
            )

        files = manifest.get(
            "files"
        )
        if not isinstance(
            files,
            list,
        ):
            raise BackupIntegrityError(
                "backup manifest files must be a list"
            )

        manifest_paths = []
        for entry in files:
            if not isinstance(
                entry,
                dict,
            ):
                raise BackupIntegrityError(
                    "invalid backup manifest file entry"
                )
            relative = _validate_archive_name(
                str(
                    entry.get(
                        "path"
                    )
                    or ""
                )
            )
            manifest_paths.append(
                relative
            )

        expected_names = {
            "manifest.json",
            *manifest_paths,
        }

        if set(names) != expected_names:
            raise BackupIntegrityError(
                "backup archive coverage does not match manifest"
            )

        destination.mkdir(
            parents=True,
            exist_ok=True,
        )

        for entry in files:
            relative = str(
                entry["path"]
            )

            suffix = Path(
                relative
            ).suffix.lower()

            if (
                suffix
                in FORBIDDEN_ARCHIVE_SUFFIXES
            ):
                raise BackupIntegrityError(
                    "backup contains forbidden TLS/private material"
                )

            data = archive.read(
                relative
            )

            expected_size = int(
                entry.get(
                    "size",
                    -1,
                )
            )
            if len(data) != expected_size:
                raise BackupIntegrityError(
                    "backup file size mismatch: "
                    + relative
                )

            actual_hash = hashlib.sha256(
                data
            ).hexdigest().upper()

            expected_hash = str(
                entry.get(
                    "sha256"
                )
                or ""
            ).upper()

            if actual_hash != expected_hash:
                raise BackupIntegrityError(
                    "backup file hash mismatch: "
                    + relative
                )

            target = (
                destination
                / relative
            )
            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            target.write_bytes(
                data
            )

    analyzer = verify_analyzer_database(
        destination
        / PAYLOAD_ANALYZER_DB,
        require_sanitized=True,
    )

    components = manifest.get(
        "components"
    )
    if not isinstance(
        components,
        dict,
    ):
        raise BackupIntegrityError(
            "backup components metadata is invalid"
        )

    collector_config_evidence = None
    if components.get(
        "collector_config"
    ):
        collector_config_evidence = (
            verify_collector_config(
                destination
                / PAYLOAD_COLLECTOR_CONFIG
            )
        )

    collector_state_evidence = None
    if components.get(
        "collector_state_projection"
    ):
        collector_state_evidence = (
            verify_collector_state_projection(
                destination
                / PAYLOAD_COLLECTOR_STATE
            )
        )

    ml_evidence = {
        "present": False,
        "model_count": 0,
        "version_count": 0,
        "active_model_count": 0,
    }

    if components.get(
        "ml_registry"
    ):
        ml_evidence = verify_ml_registry(
            destination
            / "payload"
            / "ml_registry"
        )

    expected_evidence = (
        manifest.get(
            "evidence"
        )
        or {}
    )

    if (
        analyzer
        != expected_evidence.get(
            "analyzer"
        )
    ):
        raise BackupIntegrityError(
            "Analyzer evidence does not match manifest"
        )

    expected_collector_state = (
        expected_evidence.get(
            "collector_state"
        )
    )
    if (
        collector_state_evidence
        != expected_collector_state
    ):
        raise BackupIntegrityError(
            "Collector state evidence does not match manifest"
        )

    if (
        ml_evidence
        != expected_evidence.get(
            "ml_registry"
        )
    ):
        raise BackupIntegrityError(
            "ML registry evidence does not match manifest"
        )

    return manifest


def verify_backup(
    backup: str | Path,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="aegisguard-verify-"
    ) as temporary_name:
        manifest = _extract_and_validate(
            backup,
            Path(temporary_name),
        )

    return {
        "valid": True,
        "archive_sha256": sha256_file(
            backup
        ),
        "manifest": manifest,
    }


def _copy_atomic_file(
    source: Path,
    target: Path,
) -> None:
    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = target.with_name(
        target.name
        + ".restore-"
        + uuid.uuid4().hex
    )

    shutil.copy2(
        source,
        temporary,
    )
    os.replace(
        temporary,
        target,
    )


def _copy_replace_directory(
    source: Path,
    target: Path,
) -> None:
    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = (
        target.parent
        / (
            target.name
            + ".restore-"
            + uuid.uuid4().hex
        )
    )

    shutil.copytree(
        source,
        temporary,
    )

    if target.exists():
        shutil.rmtree(
            target
        )

    os.replace(
        temporary,
        target,
    )


def _remove_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(
            path
        )
    elif path.exists():
        path.unlink()


def _snapshot_targets(
    transaction_root: Path,
    targets: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    originals = (
        transaction_root
        / "original"
    )
    originals.mkdir(
        parents=True,
        exist_ok=True,
    )

    snapshot = []

    for item in targets:
        target = Path(
            item["target"]
        )

        recovery_path = (
            originals
            / item["label"]
        )

        existed = target.exists()

        if existed:
            if item["kind"] == "file":
                recovery_path.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                shutil.copy2(
                    target,
                    recovery_path,
                )
            else:
                shutil.copytree(
                    target,
                    recovery_path,
                )

        snapshot.append({
            "label": item["label"],
            "kind": item["kind"],
            "target": str(
                target.resolve()
            ),
            "existed": existed,
            "recovery_path": str(
                recovery_path.resolve()
            ),
        })

    return snapshot


def _restore_snapshot(
    snapshot: list[dict[str, Any]],
) -> None:
    for item in reversed(
        snapshot
    ):
        target = Path(
            item["target"]
        )
        recovery = Path(
            item["recovery_path"]
        )

        _remove_path(
            target
        )

        if not item["existed"]:
            continue

        if item["kind"] == "file":
            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            shutil.copy2(
                recovery,
                target,
            )
        else:
            shutil.copytree(
                recovery,
                target,
            )


def _transaction_path(
    transaction_root: Path,
) -> Path:
    return (
        transaction_root
        / "transaction.json"
    )


def _write_transaction(
    transaction_root: Path,
    value: dict[str, Any],
) -> None:
    _atomic_json_write(
        _transaction_path(
            transaction_root
        ),
        value,
    )


def recover_interrupted_restore(
    transaction_directory: str | Path,
) -> dict[str, Any]:
    transaction_root = Path(
        transaction_directory
    ).resolve()

    transaction_file = (
        _transaction_path(
            transaction_root
        )
    )

    if not transaction_file.is_file():
        raise RestoreSafetyError(
            "restore transaction metadata is missing"
        )

    transaction = json.loads(
        transaction_file.read_text(
            encoding="utf-8"
        )
    )

    phase = str(
        transaction.get(
            "phase"
        )
        or ""
    ).upper()

    if phase not in {
        "PREPARED",
        "APPLYING",
    }:
        raise RestoreSafetyError(
            "restore transaction is not incomplete"
        )

    snapshot = transaction.get(
        "snapshot"
    )

    if not isinstance(
        snapshot,
        list,
    ):
        raise RestoreSafetyError(
            "restore transaction snapshot is invalid"
        )

    for item in snapshot:
        recovery = Path(
            item["recovery_path"]
        )
        if (
            item.get(
                "existed"
            )
            and not recovery.exists()
        ):
            raise RestoreSafetyError(
                "restore recovery evidence is missing"
            )

    _restore_snapshot(
        snapshot
    )

    transaction["phase"] = (
        "RECOVERED_INTERRUPTED_RESTORE"
    )
    transaction[
        "recovered_at_utc"
    ] = _utc_now()

    _write_transaction(
        transaction_root,
        transaction,
    )

    originals = (
        transaction_root
        / "original"
    )
    if originals.exists():
        shutil.rmtree(
            originals
        )

    return transaction


def restore_backup(
    *,
    backup: str | Path,
    analyzer_db: str | Path,
    collector_config: str | Path | None = None,
    collector_state: str | Path | None = None,
    ml_registry: str | Path | None = None,
    apply: bool = False,
    services_stopped: bool = False,
) -> dict[str, Any]:
    analyzer_target = Path(
        analyzer_db
    ).resolve()

    with tempfile.TemporaryDirectory(
        prefix="aegisguard-restore-stage-"
    ) as temporary_name:
        staging = Path(
            temporary_name
        )

        manifest = (
            _extract_and_validate(
                backup,
                staging,
            )
        )

        components = manifest[
            "components"
        ]

        targets = [{
            "label": "analyzer_database",
            "kind": "file",
            "source": str(
                staging
                / PAYLOAD_ANALYZER_DB
            ),
            "target": str(
                analyzer_target
            ),
        }]

        if components.get(
            "collector_config"
        ):
            if collector_config is None:
                raise RestoreSafetyError(
                    "collector_config target is required by this backup"
                )
            targets.append({
                "label": "collector_config",
                "kind": "file",
                "source": str(
                    staging
                    / PAYLOAD_COLLECTOR_CONFIG
                ),
                "target": str(
                    Path(
                        collector_config
                    ).resolve()
                ),
            })

        if components.get(
            "collector_state_projection"
        ):
            if collector_state is None:
                raise RestoreSafetyError(
                    "collector_state target is required by this backup"
                )
            targets.append({
                "label": "collector_state",
                "kind": "file",
                "source": str(
                    staging
                    / PAYLOAD_COLLECTOR_STATE
                ),
                "target": str(
                    Path(
                        collector_state
                    ).resolve()
                ),
            })

        if components.get(
            "ml_registry"
        ):
            if ml_registry is None:
                raise RestoreSafetyError(
                    "ml_registry target is required by this backup"
                )
            targets.append({
                "label": "ml_registry",
                "kind": "directory",
                "source": str(
                    staging
                    / "payload"
                    / "ml_registry"
                ),
                "target": str(
                    Path(
                        ml_registry
                    ).resolve()
                ),
            })

        plan = {
            "backup_id": manifest[
                "backup_id"
            ],
            "mode": (
                "APPLY"
                if apply
                else "PLAN_ONLY"
            ),
            "targets": [
                {
                    "label": item["label"],
                    "kind": item["kind"],
                    "target": item["target"],
                }
                for item in targets
            ],
        }

        if not apply:
            return {
                "status": "VERIFIED_PLAN_ONLY",
                "plan": plan,
                "manifest": manifest,
            }

        if not services_stopped:
            raise RestoreSafetyError(
                "restore apply requires explicit services_stopped confirmation"
            )

        transaction_parent = (
            analyzer_target.parent
            / "AegisGuardRestoreTransactions"
        )
        transaction_parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        transaction_root = (
            transaction_parent
            / (
                manifest["backup_id"]
                + "-"
                + datetime.now(
                    timezone.utc
                ).strftime(
                    "%Y%m%dT%H%M%SZ"
                )
            )
        )
        transaction_root.mkdir(
            parents=False,
            exist_ok=False,
        )

        try:
            os.chmod(
                transaction_root,
                0o700,
            )
        except OSError:
            pass

        snapshot = _snapshot_targets(
            transaction_root,
            targets,
        )

        transaction = {
            "schema_version": 1,
            "backup_id": manifest[
                "backup_id"
            ],
            "started_at_utc": (
                _utc_now()
            ),
            "phase": "PREPARED",
            "snapshot": snapshot,
            "targets": [
                {
                    "label": item["label"],
                    "kind": item["kind"],
                    "target": item["target"],
                }
                for item in targets
            ],
        }

        _write_transaction(
            transaction_root,
            transaction,
        )

        try:
            transaction[
                "phase"
            ] = "APPLYING"

            _write_transaction(
                transaction_root,
                transaction,
            )

            for item in targets:
                source = Path(
                    item["source"]
                )
                target = Path(
                    item["target"]
                )

                if item["kind"] == "file":
                    _copy_atomic_file(
                        source,
                        target,
                    )
                else:
                    _copy_replace_directory(
                        source,
                        target,
                    )

            analyzer_evidence = (
                verify_analyzer_database(
                    analyzer_target,
                    require_sanitized=True,
                )
            )

            if (
                analyzer_evidence
                != manifest["evidence"][
                    "analyzer"
                ]
            ):
                raise BackupIntegrityError(
                    "restored Analyzer evidence does not match backup"
                )

            if components.get(
                "collector_config"
            ):
                verify_collector_config(
                    collector_config
                )

            if components.get(
                "collector_state_projection"
            ):
                collector_evidence = (
                    verify_collector_state_projection(
                        collector_state
                    )
                )

                if (
                    collector_evidence
                    != manifest[
                        "evidence"
                    ][
                        "collector_state"
                    ]
                ):
                    raise BackupIntegrityError(
                        "restored Collector continuity evidence does not match backup"
                    )

            if components.get(
                "ml_registry"
            ):
                ml_evidence = (
                    verify_ml_registry(
                        ml_registry
                    )
                )

                if (
                    ml_evidence
                    != manifest[
                        "evidence"
                    ][
                        "ml_registry"
                    ]
                ):
                    raise BackupIntegrityError(
                        "restored ML registry evidence does not match backup"
                    )

            transaction[
                "phase"
            ] = "COMPLETED"
            transaction[
                "completed_at_utc"
            ] = _utc_now()

            _write_transaction(
                transaction_root,
                transaction,
            )

            originals = (
                transaction_root
                / "original"
            )
            if originals.exists():
                shutil.rmtree(
                    originals
                )

            return {
                "status": "RESTORED",
                "plan": plan,
                "transaction_directory": (
                    transaction_root
                ),
                "manifest": manifest,
            }

        except Exception:
            _restore_snapshot(
                snapshot
            )

            transaction[
                "phase"
            ] = "ROLLED_BACK"
            transaction[
                "rolled_back_at_utc"
            ] = _utc_now()

            _write_transaction(
                transaction_root,
                transaction,
            )

            originals = (
                transaction_root
                / "original"
            )
            if originals.exists():
                shutil.rmtree(
                    originals
                )

            raise


def default_paths() -> dict[str, Path]:
    from backend.deployment.runtime_paths import (
        resolve_analyzer_data_dir,
        resolve_collector_config_path,
    )

    analyzer_root = (
        resolve_analyzer_data_dir()
    )
    collector_config = (
        resolve_collector_config_path()
    )

    collector_state = (
        collector_config.parent
        / "collector_state.db"
    )

    if collector_config.is_file():
        try:
            config = json.loads(
                collector_config.read_text(
                    encoding="utf-8-sig"
                )
            )
            configured_state = str(
                config.get(
                    "collector_state_file"
                )
                or ""
            ).strip()
            if configured_state:
                candidate = Path(
                    configured_state
                )
                if not candidate.is_absolute():
                    candidate = (
                        collector_config.parent
                        / candidate
                    )
                collector_state = (
                    candidate.resolve()
                )
        except Exception:
            pass

    return {
        "analyzer_db": (
            analyzer_root
            / "aegisguard.db"
        ).resolve(),
        "collector_config": (
            collector_config.resolve()
        ),
        "collector_state": (
            collector_state.resolve()
        ),
        "ml_registry": (
            analyzer_root
            / "data"
            / "ml_registry"
        ).resolve(),
    }
