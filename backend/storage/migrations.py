"""Versioned, additive SQLite migrations for AegisGuard Enterprise.

The pre-product analyzer schema remains authoritative for its existing runtime
paths. These migrations extend that database without dropping or renaming
legacy tables or columns.
"""

import sqlite3
from typing import Callable, Iterable, Tuple

from backend.storage.audit_integrity import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    GENESIS_AUDIT_HASH,
    compute_audit_event_hash,
    retention_until_for_timestamp,
)


LATEST_PLATFORM_SCHEMA_VERSION = 10
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


def _execute_script_transactionally(conn: sqlite3.Connection, script: str) -> None:
    """Execute a semicolon-delimited SQLite script without implicit commits.

    sqlite3.Connection.executescript() may implicitly commit an open
    transaction, which would invalidate the savepoint used by the migration
    runner. This helper uses sqlite3.complete_statement() and conn.execute()
    so the caller retains transaction control.
    """
    statement = ""
    for line in script.splitlines():
        statement += line + "\n"
        if sqlite3.complete_statement(statement):
            sql = statement.strip()
            statement = ""
            if sql:
                conn.execute(sql)

    if statement.strip():
        raise sqlite3.OperationalError("Incomplete SQL statement in migration script")


def _migration_001_enterprise_foundation(conn: sqlite3.Connection) -> None:
    _execute_script_transactionally(
        conn,
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


def _migration_002_collector_ingest_queue(conn: sqlite3.Connection) -> None:
    _execute_script_transactionally(
        conn,
        """
        CREATE TABLE IF NOT EXISTS collector_ingest_batches (
            batch_id TEXT PRIMARY KEY,
            collector_id TEXT NOT NULL,
            hostname TEXT NOT NULL,
            peer_ip TEXT,
            payload_json TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            max_record_id INTEGER,
            state TEXT NOT NULL DEFAULT 'QUEUED'
                CHECK(state IN ('QUEUED','PROCESSING','PROCESSED','FAILED')),
            attempts INTEGER NOT NULL DEFAULT 0,
            received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            processed_at TEXT,
            last_error TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_collector_ingest_state_received
            ON collector_ingest_batches(state, received_at);

        CREATE INDEX IF NOT EXISTS idx_collector_ingest_collector_received
            ON collector_ingest_batches(collector_id, received_at DESC);
        """
    )


def _migration_003_collector_credential_rotation(
    conn: sqlite3.Connection,
) -> None:
    _add_column_if_missing(
        conn,
        "collectors",
        "credential_rotation_id",
        "TEXT",
    )
    _add_column_if_missing(
        conn,
        "collectors",
        "credential_rotated_at",
        "TEXT",
    )


def _migration_004_collector_credential_recovery(
    conn: sqlite3.Connection,
) -> None:
    _add_column_if_missing(
        conn,
        "collectors",
        "credential_recovery_id",
        "TEXT",
    )
    _add_column_if_missing(
        conn,
        "collectors",
        "credential_recovered_at",
        "TEXT",
    )


def _migration_005_collector_certificate_identity(
    conn: sqlite3.Connection,
) -> None:
    _add_column_if_missing(
        conn,
        "collectors",
        "certificate_fingerprint",
        "TEXT",
    )
    _add_column_if_missing(
        conn,
        "collectors",
        "certificate_bound_at",
        "TEXT",
    )


def _migration_006_collector_certificate_rotation(
    conn: sqlite3.Connection,
) -> None:
    for column, definition in (
        ("pending_certificate_fingerprint", "TEXT"),
        ("certificate_rotation_id", "TEXT"),
        ("certificate_rotation_started_at", "TEXT"),
        ("certificate_rotated_at", "TEXT"),
    ):
        _add_column_if_missing(conn, "collectors", column, definition)


def _migration_007_collector_security_health(
    conn: sqlite3.Connection,
) -> None:
    for column, definition in (
        ("last_heartbeat_at", "TEXT"),
        ("heartbeat_peer_ip", "TEXT"),
        (
            "heartbeat_credential_authenticated",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        ("heartbeat_mtls_required", "INTEGER NOT NULL DEFAULT 0"),
        ("heartbeat_mtls_verified", "INTEGER NOT NULL DEFAULT 0"),
        ("heartbeat_certificate_fingerprint", "TEXT"),
        ("reported_version", "TEXT"),
        ("reported_transport_status", "TEXT"),
        ("reported_pending_batches", "INTEGER"),
        ("reported_checkpoint", "INTEGER"),
        ("reported_collection_cursor", "INTEGER"),
        ("reported_retry_in_seconds", "REAL"),
        ("reported_last_successful_ack_at", "REAL"),
        ("reported_certificate_rotation_pending", "INTEGER"),
        ("reported_health_json", "TEXT NOT NULL DEFAULT '{}'"),
    ):
        _add_column_if_missing(conn, "collectors", column, definition)


def _migration_008_application_login_throttle(
    conn: sqlite3.Connection,
) -> None:
    _execute_script_transactionally(
        conn,
        """
        CREATE TABLE IF NOT EXISTS auth_login_throttle (
            username TEXT NOT NULL,
            peer_ip TEXT NOT NULL,
            failure_count INTEGER NOT NULL DEFAULT 0,
            window_started_at TEXT NOT NULL,
            blocked_until TEXT,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(username, peer_ip)
        );

        CREATE INDEX IF NOT EXISTS idx_auth_login_throttle_blocked
            ON auth_login_throttle(blocked_until);
        """
    )


def _migration_009_audit_integrity_retention(
    conn: sqlite3.Connection,
) -> None:
    for column, definition in (
        ("chain_sequence", "INTEGER"),
        ("previous_hash", "TEXT"),
        ("event_hash", "TEXT"),
        ("retention_until", "TEXT"),
    ):
        _add_column_if_missing(
            conn,
            "audit_events",
            column,
            definition,
        )

    rows = conn.execute(
        """
        SELECT rowid,
               audit_id,
               timestamp,
               actor_user_id,
               actor_type,
               action,
               target_type,
               target_id,
               outcome,
               peer_ip,
               correlation_id,
               details_json
        FROM audit_events
        ORDER BY rowid ASC
        """
    ).fetchall()

    previous_hash = GENESIS_AUDIT_HASH
    for sequence, row in enumerate(rows, start=1):
        retention_until = retention_until_for_timestamp(
            row[2],
            DEFAULT_AUDIT_RETENTION_DAYS,
        )
        event_hash = compute_audit_event_hash(
            chain_sequence=sequence,
            audit_id=row[1],
            timestamp=row[2],
            actor_user_id=row[3],
            actor_type=row[4],
            action=row[5],
            target_type=row[6],
            target_id=row[7],
            outcome=row[8],
            peer_ip=row[9],
            correlation_id=row[10],
            details_json=row[11],
            retention_until=retention_until,
            previous_hash=previous_hash,
        )
        conn.execute(
            """
            UPDATE audit_events
            SET chain_sequence = ?,
                previous_hash = ?,
                event_hash = ?,
                retention_until = ?
            WHERE rowid = ?
            """,
            (
                sequence,
                previous_hash,
                event_hash,
                retention_until,
                row[0],
            ),
        )
        previous_hash = event_hash

    _execute_script_transactionally(
        conn,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_chain_sequence
            ON audit_events(chain_sequence);

        CREATE INDEX IF NOT EXISTS idx_audit_retention_until
            ON audit_events(retention_until);

        CREATE TRIGGER IF NOT EXISTS trg_audit_retention_delete
        BEFORE DELETE ON audit_events
        WHEN OLD.retention_until IS NULL
          OR datetime(OLD.retention_until) > CURRENT_TIMESTAMP
        BEGIN
            SELECT RAISE(
                ABORT,
                'audit event retention active'
            );
        END;
        """
    )


def _migration_010_unified_incident_platform(
    conn: sqlite3.Connection,
) -> None:
    # Platform migrations are also used by isolated auth/platform tests where
    # the legacy Analyzer schema has not been initialized first. Migration v1
    # deliberately tolerated a missing legacy incidents table, so v10 must
    # self-heal that historical case instead of assuming the table exists.
    #
    # Use the complete legacy-compatible base shape here. If the Analyzer
    # schema already created the table this is a no-op; on a fresh platform
    # database it prevents later Analyzer startup from inheriting an
    # incomplete incidents table.
    _execute_script_transactionally(
        conn,
        """
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            log_id TEXT,
            threat_type TEXT,
            hostname TEXT,
            os TEXT,
            source_ip TEXT,
            user TEXT,
            process TEXT,
            file_path TEXT,
            severity TEXT,
            timestamp TEXT,
            status TEXT,
            action_taken TEXT,
            command_executed TEXT,
            playbook_steps TEXT,
            incident_report TEXT,
            alert_status TEXT,
            mitre TEXT
        );
        """
    )

    # A legacy database may contain only a partial incidents table. Re-assert
    # the complete legacy Analyzer column shape first, then the platform/S6
    # columns. _add_column_if_missing() keeps this additive and idempotent.
    for column, definition in (
        ("log_id", "TEXT"),
        ("threat_type", "TEXT"),
        ("hostname", "TEXT"),
        ("os", "TEXT"),
        ("source_ip", "TEXT"),
        ("user", "TEXT"),
        ("process", "TEXT"),
        ("file_path", "TEXT"),
        ("severity", "TEXT"),
        ("timestamp", "TEXT"),
        ("status", "TEXT"),
        ("action_taken", "TEXT"),
        ("command_executed", "TEXT"),
        ("playbook_steps", "TEXT"),
        ("incident_report", "TEXT"),
        ("alert_status", "TEXT"),
        ("mitre", "TEXT"),
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
        ("candidate_id", "TEXT"),
        ("candidate_fingerprint", "TEXT"),
        ("confidence", "REAL"),
        ("attack_story_id", "TEXT"),
        ("attack_story_version", "TEXT"),
        ("opened_at", "TEXT"),
        ("resolution_summary", "TEXT"),
    ):
        _add_column_if_missing(
            conn,
            "incidents",
            column,
            definition,
        )

    conn.execute(
        """
        UPDATE incidents
        SET title = COALESCE(
                NULLIF(title, ''),
                NULLIF(threat_type, ''),
                incident_id
            ),
            lifecycle_status = COALESCE(
                NULLIF(lifecycle_status, ''),
                'OPEN'
            ),
            opened_at = COALESCE(
                NULLIF(opened_at, ''),
                NULLIF(timestamp, ''),
                CURRENT_TIMESTAMP
            ),
            updated_at = COALESCE(
                NULLIF(updated_at, ''),
                NULLIF(timestamp, ''),
                CURRENT_TIMESTAMP
            )
        """
    )

    _execute_script_transactionally(
        conn,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_candidate_id
            ON incidents(candidate_id)
            WHERE candidate_id IS NOT NULL
              AND candidate_id != '';

        CREATE INDEX IF NOT EXISTS idx_incidents_lifecycle_updated
            ON incidents(lifecycle_status, updated_at DESC);

        CREATE INDEX IF NOT EXISTS idx_incidents_assigned_updated
            ON incidents(assigned_user_id, updated_at DESC);

        CREATE TABLE IF NOT EXISTS incident_finding_refs (
            incident_id TEXT NOT NULL,
            finding_id TEXT NOT NULL,
            PRIMARY KEY(incident_id, finding_id),
            FOREIGN KEY(incident_id)
                REFERENCES incidents(incident_id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS incident_event_refs (
            incident_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            PRIMARY KEY(incident_id, event_id),
            FOREIGN KEY(incident_id)
                REFERENCES incidents(incident_id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS incident_mitre_mappings (
            incident_id TEXT NOT NULL,
            technique_id TEXT NOT NULL,
            technique TEXT NOT NULL,
            tactic TEXT NOT NULL,
            PRIMARY KEY(
                incident_id,
                technique_id,
                tactic
            ),
            FOREIGN KEY(incident_id)
                REFERENCES incidents(incident_id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS incident_related_entities (
            incident_id TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_value TEXT NOT NULL,
            PRIMARY KEY(
                incident_id,
                entity_type,
                entity_value
            ),
            FOREIGN KEY(incident_id)
                REFERENCES incidents(incident_id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS incident_notes (
            note_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            author_user_id TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(incident_id)
                REFERENCES incidents(incident_id)
                ON DELETE CASCADE,
            FOREIGN KEY(author_user_id)
                REFERENCES users(user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_incident_notes_incident_created
            ON incident_notes(incident_id, created_at);

        CREATE TABLE IF NOT EXISTS incident_evidence_refs (
            evidence_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            reference_type TEXT NOT NULL,
            reference_id TEXT NOT NULL,
            description TEXT,
            added_by_user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(
                incident_id,
                reference_type,
                reference_id
            ),
            FOREIGN KEY(incident_id)
                REFERENCES incidents(incident_id)
                ON DELETE CASCADE,
            FOREIGN KEY(added_by_user_id)
                REFERENCES users(user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_incident_evidence_incident_created
            ON incident_evidence_refs(incident_id, created_at);

        CREATE TABLE IF NOT EXISTS incident_lifecycle_history (
            history_id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT,
            actor_user_id TEXT,
            action TEXT NOT NULL,
            reason TEXT,
            administrative_override INTEGER NOT NULL DEFAULT 0
                CHECK(administrative_override IN (0,1)),
            created_at TEXT NOT NULL,
            FOREIGN KEY(incident_id)
                REFERENCES incidents(incident_id)
                ON DELETE CASCADE,
            FOREIGN KEY(actor_user_id)
                REFERENCES users(user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_incident_history_incident_created
            ON incident_lifecycle_history(incident_id, created_at);
        """
    )


MIGRATIONS: Iterable[Migration] = (
    (1, "enterprise_foundation", _migration_001_enterprise_foundation),
    (2, "collector_ingest_queue", _migration_002_collector_ingest_queue),
    (
        3,
        "collector_credential_rotation",
        _migration_003_collector_credential_rotation,
    ),
    (
        4,
        "collector_credential_recovery",
        _migration_004_collector_credential_recovery,
    ),
    (
        5,
        "collector_certificate_identity",
        _migration_005_collector_certificate_identity,
    ),
    (
        6,
        "collector_certificate_rotation",
        _migration_006_collector_certificate_rotation,
    ),
    (
        7,
        "collector_security_health",
        _migration_007_collector_security_health,
    ),
    (
        8,
        "application_login_throttle",
        _migration_008_application_login_throttle,
    ),
    (
        9,
        "audit_integrity_retention",
        _migration_009_audit_integrity_retention,
    ),
    (
        10,
        "unified_incident_platform",
        _migration_010_unified_incident_platform,
    ),
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
