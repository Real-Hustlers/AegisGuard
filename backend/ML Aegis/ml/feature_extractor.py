import json
import csv
import os
from collections import Counter

# =====================================================
# Configuration
# =====================================================

DATA_FOLDER = "generated_logs"
OUTPUT_CSV = "training_dataset.csv"

FEATURES = [
    "FAILED_LOGIN",
    "LOGON_SUCCESS",
    "AUTHENTICATION_FAILURE",
    "SUDO_COMMAND",
    "PRIVILEGE_ESCALATION",
    "FILE_MODIFIED",
    "FILE_DELETED",
    "USB_CONNECTED",
    "DEFENDER_ALERT",
    "PASSWORD_CHANGED",
    "USER_CREATED",
    "USER_DELETED",
    "KERNEL_EVENT"
]

rows = []

# =====================================================
# Check folder exists
# =====================================================

if not os.path.exists(DATA_FOLDER):
    print(f"ERROR: Folder '{DATA_FOLDER}' not found!")
    exit()

files = [f for f in os.listdir(DATA_FOLDER) if f.endswith(".json")]

if len(files) == 0:
    print("ERROR: No JSON files found!")
    exit()

print(f"Found {len(files)} investigation files.\n")

# =====================================================
# Process each investigation
# =====================================================

for filename in files:

    filepath = os.path.join(DATA_FOLDER, filename)

    try:
        with open(filepath, "r") as f:
            data = json.load(f)

    except Exception as e:
        print(f"Skipping {filename}: {e}")
        continue

    machine_id = data.get("machine_id", filename.replace(".json", ""))
    hostname = data.get("hostname", "")
    operating_system = data.get("os", "")

    logs = data.get("logs", [])

    counts = Counter()

    users = set()
    source_ips = set()

    high_events = 0
    critical_events = 0

    for log in logs:

        event = log.get("event_type", "")
        counts[event] += 1

        if log.get("user"):
            users.add(log["user"])

        if log.get("source_ip"):
            source_ips.add(log["source_ip"])

        severity = log.get("severity", "").upper()

        if severity == "HIGH":
            high_events += 1

        elif severity == "CRITICAL":
            critical_events += 1

    row = {
        "machine_id": machine_id,
        "hostname": hostname,
        "os": operating_system
    }

    for feature in FEATURES:
        row[feature] = counts.get(feature, 0)

    row["TOTAL_EVENTS"] = len(logs)
    row["HIGH_EVENTS"] = high_events
    row["CRITICAL_EVENTS"] = critical_events
    row["UNIQUE_USERS"] = len(users)
    row["UNIQUE_SOURCE_IPS"] = len(source_ips)

    # ------------------------------------
    # Label from filename
    # ------------------------------------

    filename_upper = filename.upper()

    if filename_upper.startswith("NORMAL"):
        row["LABEL"] = "NORMAL"

    elif filename_upper.startswith("BRUTE_FORCE"):
        row["LABEL"] = "BRUTE_FORCE"

    elif filename_upper.startswith("MALWARE"):
        row["LABEL"] = "MALWARE"

    elif filename_upper.startswith("PRIVILEGE_ESCALATION"):
        row["LABEL"] = "PRIVILEGE_ESCALATION"

    elif filename_upper.startswith("INSIDER_THREAT"):
        row["LABEL"] = "INSIDER_THREAT"

    else:
        row["LABEL"] = "UNKNOWN"

    rows.append(row)

# =====================================================
# CSV Columns
# =====================================================

fieldnames = [
    "machine_id",
    "hostname",
    "os",
]

fieldnames.extend(FEATURES)

fieldnames.extend([
    "TOTAL_EVENTS",
    "HIGH_EVENTS",
    "CRITICAL_EVENTS",
    "UNIQUE_USERS",
    "UNIQUE_SOURCE_IPS",
    "LABEL"
])

# =====================================================
# Write CSV
# =====================================================

with open(OUTPUT_CSV, "w", newline="") as csvfile:

    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    writer.writerows(rows)

# =====================================================
# Summary
# =====================================================

print("=" * 60)
print("AEGISGUARD FEATURE EXTRACTION COMPLETED")
print("=" * 60)
print(f"Files Found            : {len(files)}")
print(f"Rows Written           : {len(rows)}")
print(f"Output CSV             : {OUTPUT_CSV}")
print("=" * 60)
