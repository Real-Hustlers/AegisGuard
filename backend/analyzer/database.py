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

    cursor.execute("""
        INSERT OR IGNORE INTO settings
        (key, value)
        VALUES (
            'simulation_mode',
            'true'
        )
    """)

    conn.commit()