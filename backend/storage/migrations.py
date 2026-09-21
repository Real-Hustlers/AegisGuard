"""Versioned, additive SQLite migrations for AegisGuard Enterprise.

The pre-product analyzer schema remains authoritative for its existing runtime
paths. These migrations extend that database without dropping or renaming
legacy tables or columns.
"""

import sqlite3
from typing import Callable, Iterable, Tuple


LATEST_PLATFORM_SCHEMA_VERSION = 1
Migration = Tuple[int, str, Callable[[sqlite3.Connection], None]]


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row is not None


def _columns(conn: sqlite3.Connection, table: str) -> set:
    if not _table_exists(conn, table):
        return set()
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _add_column_if_missing(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    if _table_exists(conn, table) and column not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _migration_001_enterprise_foundation(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('ADMINISTRATOR','ANALYST','VIEWER')),
            active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            revoked_at TEXT,
            peer_ip TEXT,
            user_agent TEXT,
            FOREIGN KEY(user_id) REFERENCES users(user_id)
        );

        CREATE TABLE IF NOT EXISTS collectors (
            collector_id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            display_name TEXT,
            version TEXT,
            status TEXT NOT NULL DEFAULT 'ENROLLED',
            credential_fingerprint TEXT,
            enrolled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TEXT,
            revoked_at TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS assets (
            asset_id TEXT PRIMARY KEY,
            collector_id TEXT,
            hostname TEXT NOT NULL,
            os TEXT,
            primary_ip TEXT,
            first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(collector_id) REFERENCES collectors(collector_id)
        );

        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            legacy_log_id TEXT UNIQUE,
            collector_id TEXT,
            asset_id TEXT,
            observed_at TEXT NOT NULL,
            received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT NOT NULL,
            severity TEXT,
            user_name TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            process_name TEXT,
            file_path TEXT,
            raw_log_hash TEXT,
            normalized_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(collector_id) REFERENCES collectors(collector_id),
            FOREIGN KEY(asset_id) REFERENCES assets(asset_id)
        );

        CREATE TABLE IF NOT EXISTS detections (
            detection_id TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            detected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            detector TEXT NOT NULL,
            detection_type TEXT NOT NULL,
            score REAL,
            severity TEXT,
            mitre_json TEXT NOT NULL DEFAULT '{}',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(event_id) REFERENCES events(event_id)
        );

        CREATE TABLE IF NOT EXISTS incident_events (
            incident_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            relation_type TEXT NOT NULL DEFAULT 'EVIDENCE',
            attached_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(incident_id, event_id),
            FOREIGN KEY(incident_id) REFERENCES incidents(incident_id),
            FOREIGN KEY(event_id) REFERENCES events(event_id)
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            audit_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            actor_user_id TEXT,
            actor_type TEXT NOT NULL DEFAULT 'SYSTEM',
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            outcome TEXT NOT NULL,
            peer_ip TEXT,
            correlation_id TEXT,
            details_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(actor_user_id) REFERENCES users(user_id)
        );

        CREATE TABLE IF NOT EXISTS model_metadata (
            model_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            stage TEXT NOT NULL DEFAULT 'CANDIDATE',
            artifact_hash TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            promoted_at TEXT,
            promoted_by_user_id TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(name, version),
            FOREIGN KEY(promoted_by_user_id) REFERENCES users(user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_user_active
            ON sessions(user_id, revoked_at, expires_at);
        CREATE INDEX IF NOT EXISTS idx_collectors_last_seen
            ON collectors(last_seen_at DESC);
        CREATE INDEX IF NOT EXISTS idx_assets_hostname
            ON assets(hostname);
        CREATE INDEX IF NOT EXISTS idx_events_observed
            ON events(observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_events_collector_observed
            ON events(collector_id, observed_at DESC);
        CREATE INDEX IF NOT EXISTS idx_detections_event
            ON detections(event_id, detected_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_actor
            ON audit_events(actor_user_id, timestamp DESC);
        """
    )

    # Extend legacy incident/response tables without changing their existing
    # status fields or pre-product behavior.
    for column, definition in (
        ("title", "TEXT"),
        ("description", "TEXT"),
        ("lifecycle_status", "TEXT NOT NULL DEFAULT 'OPEN'"),
        ("priority", "TEXT"),
        ("assigned_user_id", "TEXT"),
        ("updated_at", "TEXT"),
        ("resolved_at", "TEXT"),
        ("closed_at", "TEXT"),
        ("disposition", "TEXT"),
        ("notes", "TEXT"),
    ):
        _add_column_if_missing(conn, "incidents", column, definition)

    for column, definition in (
        ("requested_by_user_id", "TEXT"),
        ("approved_by_user_id", "TEXT"),
        ("approval_required", "INTEGER NOT NULL DEFAULT 1"),
        ("simulation_result", "TEXT"),
        ("updated_at", "TEXT"),
    ):
        _add_column_if_missing(conn, "response_actions", column, definition)


MIGRATIONS: Iterable[Migration] = (
    (1, "enterprise_foundation", _migration_001_enterprise_foundation),
)


def get_platform_schema_version(conn: sqlite3.Connection) -> int:
    if not _table_exists(conn, "platform_schema_migrations"):
        return 0
    row = conn.execute(
        "SELECT COALESCE(MAX(version), 0) FROM platform_schema_migrations"
    ).fetchone()
    return int(row[0] if row else 0)


def ensure_platform_schema(conn: sqlite3.Connection) -> int:
    """Apply all pending additive platform migrations and return the version."""

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS platform_schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    applied = {
        int(row[0])
        for row in conn.execute(
            "SELECT version FROM platform_schema_migrations"
        ).fetchall()
    }

    for version, name, migration in MIGRATIONS:
        if version in applied:
            continue

        savepoint = f"aegisguard_platform_migration_{version}"
        conn.execute(f"SAVEPOINT {savepoint}")
        try:
            migration(conn)
            conn.execute(
                "INSERT INTO platform_schema_migrations(version, name) VALUES (?, ?)",
                (version, name),
            )
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        except Exception:
            conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            conn.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise

    return get_platform_schema_version(conn)
