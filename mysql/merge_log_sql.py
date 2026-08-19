import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path


# ============================================================
# APPLICATION ROOT
# ============================================================

if getattr(sys, "frozen", False):
    # Packaged Analyzer:
    # C:\Users\saran\makethon\dist\app.exe
    APP_ROOT = Path(sys.executable).resolve().parent
else:
    # Source project:
    # C:\Users\saran\makethon
    APP_ROOT = Path(__file__).resolve().parents[3]


# ============================================================
# DATABASE / INPUT PATHS
# ============================================================

DB_PATH = APP_ROOT / "mysql" / "aegisguard.db"

DEFAULT_JSON_PATH = (
    APP_ROOT
    / "output"
    / "classified_logs.json"
)


# ============================================================
# TIMESTAMP NORMALIZATION
# ============================================================

def _normalize_timestamp(value):

    if not value:
        return None

    # Already a datetime object
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")

    value = str(value)

    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ]

    for pattern in formats:

        try:
            return datetime.strptime(
                value,
                pattern
            ).strftime("%Y-%m-%d %H:%M:%S")

        except ValueError:
            continue

    return value


# ============================================================
# IMPORT CLASSIFIED LOGS
# ============================================================

def import_classified_logs_to_db(
    json_path=None,
    db_path=None
):

    json_path = Path(
        json_path or DEFAULT_JSON_PATH
    )

    db_path = Path(
        db_path or DB_PATH
    )

    print("=" * 70, flush=True)

    print(
        f"SQLite database: {db_path}",
        flush=True
    )

    print(
        f"Classified logs: {json_path}",
        flush=True
    )

    # --------------------------------------------------------
    # Make sure directories exist
    # --------------------------------------------------------

    db_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    json_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Check JSON
    # --------------------------------------------------------

    if not json_path.exists():

        print(
            f"No classified log file found at {json_path}",
            flush=True
        )

        return 0

    # --------------------------------------------------------
    # Load classified logs
    # --------------------------------------------------------

    with open(
        json_path,
        "r",
        encoding="utf-8"
    ) as handle:

        logs = json.load(handle)

    if not isinstance(logs, list):

        print(
            "classified_logs.json does not contain a list.",
            flush=True
        )

        return 0

    # --------------------------------------------------------
    # Connect to SAME database used by Analyzer
    # --------------------------------------------------------

    conn = sqlite3.connect(
        str(db_path)
    )

    cursor = conn.cursor()

    # --------------------------------------------------------
    # Create table if required
    # --------------------------------------------------------

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
    # Schema migrations
    # --------------------------------------------------------

    migrations = [
        "ALTER TABLE security_logs ADD COLUMN ml_prediction TEXT",
        "ALTER TABLE security_logs ADD COLUMN ml_confidence REAL",
        "ALTER TABLE security_logs ADD COLUMN threat_category TEXT",
        "ALTER TABLE security_logs ADD COLUMN threat_score INTEGER",
        "ALTER TABLE security_logs ADD COLUMN threat_level TEXT",
    ]

    for column_sql in migrations:

        try:
            cursor.execute(column_sql)

        except sqlite3.OperationalError:
            # Column already exists
            pass

    # --------------------------------------------------------
    # Insert / update logs
    # --------------------------------------------------------

    query = """
    INSERT OR REPLACE INTO security_logs (
        log_id,
        machine_id,
        hostname,
        os,
        timestamp,
        event_type,
        user,
        source_ip,
        destination_ip,
        process,
        file_path,
        severity,
        raw_log,
        ml_prediction,
        ml_confidence,
        threat_category,
        threat_score,
        threat_level
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """

    count = 0

    for log in logs:

        timestamp = _normalize_timestamp(
            log.get("timestamp")
        )

        severity_value = (
            log.get("severity")
            or log.get("threat_level")
            or "LOW"
        )

        values = (

            # Primary ID
            log.get("log_id"),

            # Machine information
            log.get("machine_id"),

            log.get("hostname"),

            log.get("os"),

            # Time / event
            timestamp,

            log.get("event_type"),

            # User / network
            log.get("user"),

            log.get("source_ip"),

            log.get("destination_ip"),

            # Process / file
            log.get("process"),

            log.get("file_path"),

            # Severity
            severity_value,

            # Raw event
            log.get("raw_log"),

            # ML fields
            log.get("ml_prediction"),

            log.get("ml_confidence"),

            log.get("threat_category"),

            log.get("threat_score"),

            log.get("threat_level"),
        )

        cursor.execute(
            query,
            values
        )

        count += 1

    # --------------------------------------------------------
    # Commit
    # --------------------------------------------------------

    conn.commit()

    # --------------------------------------------------------
    # Verify database count
    # --------------------------------------------------------

    cursor.execute(
        "SELECT COUNT(*) FROM security_logs"
    )

    total_rows = cursor.fetchone()[0]

    conn.close()

    print(
        f"Imported {count} classified logs into SQLite",
        flush=True
    )

    print(
        f"Total security_logs rows: {total_rows}",
        flush=True
    )

    print("=" * 70, flush=True)

    return count


if __name__ == "__main__":

    import_classified_logs_to_db()