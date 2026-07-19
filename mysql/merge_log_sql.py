import json
import sqlite3
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "mysql" / "aegisguard.db"
DEFAULT_JSON_PATH = BASE_DIR / "backend" / "analyzer" / "ingestion" / "output" / "classified_logs.json"


def _normalize_timestamp(value):
    if not value:
        return None

    for pattern in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, pattern).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

    return value


def import_classified_logs_to_db(json_path=None, db_path=None):
    json_path = Path(json_path or DEFAULT_JSON_PATH)
    db_path = Path(db_path or DB_PATH)

    if not json_path.exists():
        print(f"No classified log file found at {json_path}")
        return 0

    with open(json_path, "r", encoding="utf-8") as handle:
        logs = json.load(handle)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

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

    for column_sql in [
        "ALTER TABLE security_logs ADD COLUMN ml_prediction TEXT",
        "ALTER TABLE security_logs ADD COLUMN ml_confidence REAL",
        "ALTER TABLE security_logs ADD COLUMN threat_category TEXT",
        "ALTER TABLE security_logs ADD COLUMN threat_score INTEGER",
        "ALTER TABLE security_logs ADD COLUMN threat_level TEXT",
    ]:
        try:
            cursor.execute(column_sql)
        except sqlite3.OperationalError:
            pass

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
        timestamp = _normalize_timestamp(log.get("timestamp"))
        severity_value = log.get("severity") or (log.get("threat_level") or "LOW")

        values = (
            log.get("log_id"),
            log.get("machine_id"),
            log.get("hostname"),
            log.get("os"),
            timestamp,
            log.get("event_type"),
            log.get("user"),
            log.get("source_ip"),
            log.get("destination_ip"),
            log.get("process"),
            log.get("file_path"),
            severity_value,
            log.get("raw_log"),
            log.get("ml_prediction"),
            log.get("ml_confidence"),
            log.get("threat_category"),
            log.get("threat_score"),
            log.get("threat_level"),
        )

        cursor.execute(query, values)
        count += 1

    conn.commit()
    conn.close()

    print(f"Imported {count} classified logs into SQLite")
    return count


if __name__ == "__main__":
    import_classified_logs_to_db()