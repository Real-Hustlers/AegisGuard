# merge_logs.py
#
# Merges all machine JSON files into a single JSON while
# preserving machine information and assigning a unique log ID.
#

import os
import json
from glob import glob

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ANALYZER_DIR = os.path.dirname(BASE_DIR)

INPUT_FOLDER = os.path.join(ANALYZER_DIR, "test")
OUTPUT_FOLDER = os.path.join(ANALYZER_DIR, "output")
OUTPUT_FILE = "merged_logs.json"


def merge_logs():
    all_logs = []
    log_counter = 1

    json_files = glob(os.path.join(INPUT_FOLDER, "*.json"))

    if not json_files:
        print("No machine JSON files found.")
        return

    for file in json_files:

        try:
            with open(file, "r") as f:
                machine = json.load(f)

            machine_id = machine.get("machine_id", "UNKNOWN")
            hostname = machine.get("hostname", "UNKNOWN")
            operating_system = machine.get("os", "UNKNOWN")

            logs = machine.get("logs", [])

            for log in logs:

                merged_log = {
                    "log_id": f"LOG-{log_counter:06d}",
                    "machine_id": machine_id,
                    "hostname": hostname,
                    "os": operating_system,

                    "timestamp": log.get("timestamp"),
                    "event_type": log.get("event_type"),
                    "user": log.get("user"),
                    "source_ip": log.get("source_ip"),
                    "destination_ip": log.get("destination_ip"),
                    "process": log.get("process"),
                    "file_path": log.get("file_path"),
                    "severity": log.get("severity"),
                    "raw_log": log.get("raw_log")
                }

                all_logs.append(merged_log)
                log_counter += 1

        except Exception as e:
            print(f"Error reading {file}: {e}")

    # Sort chronologically
    all_logs.sort(key=lambda x: x["timestamp"] or "")

    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    with open(os.path.join(OUTPUT_FOLDER, OUTPUT_FILE), "w") as f:
        json.dump(all_logs, f, indent=4)

    print(f"\nMerged {len(json_files)} machine files")
    print(f"Total Logs : {len(all_logs)}")
    print(f"Saved to : {os.path.join(OUTPUT_FOLDER, OUTPUT_FILE)}")


if __name__ == "__main__":
    merge_logs()