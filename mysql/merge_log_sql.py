import json
import os
import sqlite3
from datetime import datetime

# -------------------------------
# Connect to SQLite Database
# -------------------------------
db_path = os.path.join(os.path.dirname(__file__), "aegisguard.db")
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# -------------------------------
# Locate merged_logs.json
# -------------------------------
import os

json_path = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "backend",
        "collector",
        "windows_logs.json"
    )
)

print("Reading JSON from:")
print(json_path)

# -------------------------------
# Read JSON file
# -------------------------------
with open(json_path, "r", encoding="utf-8") as f:
    logs = json.load(f)

# -------------------------------
# Insert Query
# -------------------------------
query = """
INSERT OR IGNORE INTO security_logs (
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
    raw_log
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

count = 0

# -------------------------------
# Insert Logs
# -------------------------------
for log in logs:

    timestamp = log.get("timestamp")

    if timestamp:
        try:
            timestamp = datetime.strptime(
                timestamp,
                "%Y-%m-%dT%H:%M:%SZ"
            ).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            timestamp = None

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
        log.get("severity"),
        log.get("raw_log")
    )

    cursor.execute(query, values)

    if cursor.rowcount == 1:
        count += 1

# -------------------------------
# Save Changes
# -------------------------------
conn.commit()

print(f"\n✅ Imported {count} logs into SQLite successfully!")

cursor.close()
conn.close()