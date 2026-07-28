import json
import platform
import requests
import time
import subprocess

from parser import parse_event
from detector import detect_threat
from config_loader import load_config

ANALYZER = "http://127.0.0.1:5000/api/upload_logs"


def send_log(parsed_log):
    payload = {
        "machine_id": platform.node(),
        "hostname": platform.node(),
        "os": platform.platform(),
        "logs": [parsed_log]
    }

    try:
        requests.post(ANALYZER, json=payload, timeout=5)
    except Exception as e:
        print("Upload failed:", e)


def get_latest_record_id():
    cmd = r"""
Get-WinEvent -LogName Security -MaxEvents 1 |
Select-Object RecordId |
ConvertTo-Json
"""

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            cmd
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    if not result.stdout.strip():
        return 0

    obj = json.loads(result.stdout)
    return obj["RecordId"]


def collect_new_events(last_record_id):

    config = load_config()

    ids = ",".join(str(i) for i in config["event_ids"])

    cmd = f"""
    Get-WinEvent -LogName Security |
    Where-Object {{
        $_.RecordId -gt {last_record_id} -and
        $_.Id -in @({ids})
    }} |
    Sort-Object RecordId |
    Select-Object RecordId,
                Id,
                TimeCreated,
                MachineName,
                LevelDisplayName,
                Message |
    ConvertTo-Json -Depth 4
    """

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            cmd
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    if not result.stdout.strip():
        return []

    logs = json.loads(result.stdout)

    if isinstance(logs, dict):
        logs = [logs]

    return logs


def start_live_monitor(last_record=None):

    print("=" * 60)
    print("Live Windows Security Monitor Started")
    print("=" * 60)

    if last_record is None:
        last_record = get_latest_record_id()

    print("Starting from RecordID:", last_record)

    while True:

        events = collect_new_events(last_record)

        for event in events:

            parsed = parse_event(event)
            parsed["record_id"] = event["RecordId"]
            parsed["threat_level"] = detect_threat(parsed)
            send_log(parsed)

            print(
                f"[+] {event['RecordId']} "
                f"{parsed['event_type']} "
                f"{parsed['user']}"
            )

            last_record = max(last_record, event["RecordId"])
            print(event["RecordId"])

        time.sleep(2)


if __name__ == "__main__":
    start_live_monitor()