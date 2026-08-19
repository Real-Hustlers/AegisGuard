import subprocess
import json
from datetime import datetime, timedelta
import requests
import platform
from config_loader import load_config

config = load_config()
ANALYZER = config["analyzer_url"]

def send_logs(parsed_logs):

    payload = {
        "machine_id": platform.node(),
        "hostname": platform.node(),
        "os": platform.platform(),
        "logs": parsed_logs
    }

    response = requests.post(
        ANALYZER,
        json=payload
    )

    print(response.text)


def collect_security_logs(hours=HOURS, max_events=MAX_EVENTS):
    """
    Collect important Windows Security logs from the last 'hours' hours.
    """

    # Calculate start time
    start_time = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")

    powershell_command = f"""
    Get-WinEvent -LogName Security -MaxEvents {max_events} |
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
            powershell_command,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    print("Start Time:", start_time)
    print("PowerShell Command:")
    print(powershell_command)

    if result.returncode != 0:
        print("PowerShell Error:")
        print(result.stderr)
        return []

    print("STDOUT:")
    print(result.stdout)

    print("STDERR:")
    print(result.stderr)

    if not result.stdout.strip():
        return []

    try:
        logs = json.loads(result.stdout)

        if isinstance(logs, dict):
            logs = [logs]

        return logs

    except json.JSONDecodeError:
        print("Failed to parse PowerShell JSON output.")
        return []


def save_raw_logs(logs, filename="raw_security_logs.json"):
    """
    Save collected raw logs to JSON.
    """

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(logs, file, indent=4, default=str)

    print(f"Raw logs saved to '{filename}'")


if __name__ == "__main__":


    HOURS = config["hours"]
    MAX_EVENTS = config["max_events"]

    print("=" * 50)
    print("Windows Security Log Collector")
    print("=" * 50)

    logs = collect_security_logs(
        hours=HOURS,
        max_events=MAX_EVENTS
    )

    print(f"\nCollected {len(logs)} Security Events\n")

    if logs:
        print("First Event:\n")
        print(
            json.dumps(
                logs[0],
                indent=4,
                default=str
            )
        )

        # Save locally
        save_raw_logs(logs)

        # Send to Analyzer
        send_logs(logs)

    else:
        print("No matching Security events found.")