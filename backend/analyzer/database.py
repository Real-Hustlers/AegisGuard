import hashlib
import json
import sqlite3
import sys
import threading
from pathlib import Path


# ============================================================
# DATABASE PATH
# ============================================================

if getattr(sys, "frozen", False):
    # Running from PyInstaller EXE
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    # Running normally from source
    BASE_DIR = Path(__file__).resolve().parents[2]

DB_PATH = BASE_DIR / "aegisguard.db"

DB_PATH.parent.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# SCHEMA INITIALIZATION CONTROL
# ============================================================

_schema_initialized = False
_schema_lock = threading.Lock()


def get_database_path():
    """Return the single writable database used by this Analyzer process."""

    return DB_PATH.resolve()


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    """
    Open a SQLite connection configured for concurrent
    Flask reads and analyzer writes.
    """

    global _schema_initialized

    DB_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    conn = sqlite3.connect(
        str(DB_PATH),

        # Wait before failing when another request is writing.
        timeout=30,

        # Flask requests can execute in different threads.
        check_same_thread=False
    )

    conn.row_factory = sqlite3.Row

    # --------------------------------------------------------
    # SQLite concurrency configuration
    # --------------------------------------------------------

    conn.execute(
        "PRAGMA busy_timeout = 30000"
    )

    # WAL allows readers while another connection is writing.
    conn.execute(
        "PRAGMA journal_mode = WAL"
    )

    conn.execute(
        "PRAGMA synchronous = NORMAL"
    )

    conn.execute(
        "PRAGMA foreign_keys = ON"
    )

    # --------------------------------------------------------
    # Initialize schema only once per running process
    # --------------------------------------------------------

    if not _schema_initialized:

        with _schema_lock:

            if not _schema_initialized:

                ensure_schema(conn)

                _schema_initialized = True

    return conn


# ============================================================
# DATABASE SCHEMA
# ============================================================

def ensure_schema(conn):
    """
    Create required tables and apply migrations.

    This should run only during application initialization,
    not on every database query.
    """

    cursor = conn.cursor()

    # ========================================================
    # SECURITY LOGS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            log_id TEXT PRIMARY KEY,
        machine_id TEXT,
        hostname TEXT,
        record_id TEXT,
        os TEXT,
            timestamp TEXT,
            event_type TEXT,
            user TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            process TEXT,
            file_path TEXT,
            severity TEXT,
            raw_log TEXT,
            ml_prediction TEXT,
            ml_confidence REAL,
            threat_category TEXT,
            threat_score INTEGER,
            threat_level TEXT
        )
    """)

    # --------------------------------------------------------
    # Security log migrations
    # --------------------------------------------------------

    for column_sql in [

        "ALTER TABLE security_logs "
        "ADD COLUMN record_id TEXT",

        "ALTER TABLE security_logs "
        "ADD COLUMN ml_prediction TEXT",

        "ALTER TABLE security_logs "
        "ADD COLUMN ml_confidence REAL",

        "ALTER TABLE security_logs "
        "ADD COLUMN threat_category TEXT",

        "ALTER TABLE security_logs "
        "ADD COLUMN threat_score INTEGER",

        "ALTER TABLE security_logs "
        "ADD COLUMN threat_level TEXT",

    ]:

        try:

            cursor.execute(
                column_sql
            )

        except sqlite3.OperationalError as e:

            # Ignore only duplicate-column errors.
            if "duplicate column name" not in str(e).lower():
                raise

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_security_logs_hostname_timestamp
        ON security_logs(hostname, timestamp DESC)
    """)

    # Backfill identities written by the first incremental version, which
    # encoded RecordId in log_id but did not retain it in a separate column.
    rows = cursor.execute("""
        SELECT log_id FROM security_logs
        WHERE (record_id IS NULL OR record_id = '')
          AND log_id LIKE 'windows:%:%'
    """).fetchall()
    for row in rows:
        record_id = str(row["log_id"]).rsplit(":", 1)[-1]
        cursor.execute(
            "UPDATE security_logs SET record_id = ? WHERE log_id = ?",
            (record_id, row["log_id"]),
        )

    # This is redundant with the stable log_id primary key but makes the
    # Windows identity explicit and protects future import paths too.
    cursor.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_security_logs_hostname_record_id
        ON security_logs(hostname, record_id)
        WHERE record_id IS NOT NULL AND record_id != ''
    """)

    # ========================================================
    # INCIDENTS
    # ========================================================

    cursor.execute("""
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
        )
    """)

    # --------------------------------------------------------
    # Incident migrations
    # --------------------------------------------------------

    for column_sql in [

        "ALTER TABLE incidents "
        "ADD COLUMN incident_report TEXT",

        "ALTER TABLE incidents "
        "ADD COLUMN alert_status TEXT",

        "ALTER TABLE incidents "
        "ADD COLUMN mitre TEXT",

    ]:

        try:

            cursor.execute(
                column_sql
            )

        except sqlite3.OperationalError as e:

            if "duplicate column name" not in str(e).lower():
                raise

    # ========================================================
    # RESPONSE LOGS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS response_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT,
            timestamp TEXT,
            message TEXT
        )
    """)

    # ========================================================
    # SETTINGS
    # ========================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO settings
        (key, value)
        VALUES (
            'auto_response_enabled',
            'true'
        )
    """)

    # SOAR is intentionally opt-in for enforcement.  These defaults are safe
    # for a shared demo network: create recommendations, but never change a
    # firewall unless an operator approves it (and dry-run is disabled).
    for key, value in {
        "soar_mode": "MANUAL",
        "soar_dry_run": "true",
        "soar_auto_min_score": "90",
        "soar_allow_private_ip_blocking": "false",
        "soar_allowlist": '["127.0.0.1", "::1"]',
    }.items():
        cursor.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            (key, value),
        )

    # Each response is an immutable audit event.  action_key is deterministic
    # for a given incident/action/target, so retried uploads and concurrent
    # collectors cannot create duplicate firewall changes.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS response_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_key TEXT NOT NULL UNIQUE,
            incident_id TEXT,
            log_id TEXT,
            hostname TEXT,
            action_type TEXT NOT NULL,
            target TEXT NOT NULL,
            execution_scope TEXT NOT NULL DEFAULT 'ANALYZER',
            mode TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            requested_at TEXT NOT NULL,
            executed_at TEXT,
            error TEXT,
            rollback_status TEXT,
            metadata TEXT
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_response_actions_recent
        ON response_actions(requested_at DESC)
    """)

    # The Collector upload source is recorded separately from event source_ip.
    # This lets SOAR protect known Collector endpoints from accidental blocks.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS collector_endpoints (
            hostname TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
    """)

    cursor.execute("""
        INSERT OR IGNORE INTO settings
        (key, value)
        VALUES (
            'simulation_mode',
            'true'
        )
    """)

    conn.commit()


# ============================================================
# INCREMENTAL SECURITY-LOG INGESTION
# ============================================================

def build_log_identity(log):
    """Return the stable, retry-safe identity for an incoming event."""

    hostname = str(log.get("hostname") or log.get("machine_id") or "UNKNOWN").strip()
    record_id = log.get("record_id")

    if record_id not in (None, ""):
        return f"windows:{hostname.lower()}:{record_id}"

    # Some non-Windows sources do not provide RecordId.  Keep those retry-safe
    # too, without accidentally treating separate Windows hosts as one source.
    fingerprint = json.dumps({
        "hostname": hostname,
        "timestamp": log.get("timestamp"),
        "event_type": log.get("event_type"),
        "user": log.get("user"),
        "source_ip": log.get("source_ip"),
        "raw_log": log.get("raw_log"),
    }, sort_keys=True, default=str, separators=(",", ":"))
    return "event:" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()


def get_existing_log_ids(logs):
    """Return stable identities already persisted for the supplied batch."""

    identities = [build_log_identity(log) for log in logs]
    if not identities:
        return set()

    conn = get_connection()
    try:
        existing = set()
        # Keep each SQLite IN clause comfortably below its parameter limit.
        for offset in range(0, len(identities), 900):
            chunk = identities[offset:offset + 900]
            placeholders = ",".join("?" for _ in chunk)
            rows = conn.execute(
                f"SELECT log_id FROM security_logs WHERE log_id IN ({placeholders})",
                chunk,
            ).fetchall()
            existing.update(row["log_id"] for row in rows)
        return existing
    finally:
        conn.close()


def insert_new_security_logs(logs):
    """Insert a classified batch once and return only the newly stored logs.

    ``security_logs.log_id`` is the database-level idempotency guard.  A
    Collector retry therefore has no race window between duplicate detection
    and insertion.
    """

    if not logs:
        return []

    conn = get_connection()
    inserted = []

    try:
        cursor = conn.cursor()
        cursor.execute("BEGIN IMMEDIATE")

        query = """
            INSERT OR IGNORE INTO security_logs (
                log_id, machine_id, hostname, record_id, os, timestamp, event_type,
                user, source_ip, destination_ip, process, file_path,
                severity, raw_log, ml_prediction, ml_confidence,
                threat_category, threat_score, threat_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        for log in logs:
            log_id = build_log_identity(log)
            log["log_id"] = log_id
            cursor.execute(query, (
                log_id,
                log.get("machine_id"),
                log.get("hostname"),
                log.get("record_id"),
                log.get("os"),
                log.get("timestamp"),
                log.get("event_type"),
                log.get("user"),
                log.get("source_ip"),
                log.get("destination_ip"),
                log.get("process"),
                log.get("file_path"),
                log.get("severity"),
                log.get("raw_log"),
                log.get("ml_prediction"),
                log.get("ml_confidence"),
                log.get("threat_category"),
                log.get("threat_score"),
                log.get("threat_level"),
            ))
            if cursor.rowcount:
                inserted.append(log)

        conn.commit()
        return inserted

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def record_collector_endpoint(hostname, ip):
    """Remember the actual Collector upload peer for SOAR self-protection."""
    if not hostname or not ip:
        return
    conn = get_connection()
    try:
        conn.execute("""
            INSERT INTO collector_endpoints(hostname, ip, last_seen)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(hostname) DO UPDATE SET ip=excluded.ip, last_seen=excluded.last_seen
        """, (str(hostname), str(ip)))
        conn.commit()
    finally:
        conn.close()
