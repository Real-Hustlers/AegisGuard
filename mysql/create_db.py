import sqlite3

conn = sqlite3.connect("aegisguard.db")
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
    raw_log TEXT
)
""")

conn.commit()
conn.close()

print("✅ SQLite database created successfully!")