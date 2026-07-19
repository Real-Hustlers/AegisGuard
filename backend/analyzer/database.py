import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = BASE_DIR / "mysql" / "aegisguard.db"


def ensure_schema(conn):
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
        "ALTER TABLE incidents ADD COLUMN incident_report TEXT",
        "ALTER TABLE incidents ADD COLUMN alert_status TEXT",
        "ALTER TABLE incidents ADD COLUMN mitre TEXT",
    ]:
        try:
            cursor.execute(column_sql)
        except sqlite3.OperationalError:
            pass

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

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS response_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT,
        timestamp TEXT,
        message TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    """)

    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_response_enabled', 'true')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('simulation_mode', 'true')")

    conn.commit()


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    ensure_schema(conn)
    return conn