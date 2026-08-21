import json
import platform
import subprocess
from datetime import datetime, timedelta

import requests

from config_loader import load_config


# ============================================================
# LOAD CONFIGURATION
# ============================================================

config = load_config()

ANALYZER = config["analyzer_url"]
HOURS = int(config["hours"])
MAX_EVENTS = int(config["max_events"])


# ============================================================
# SEND LOGS TO ANALYZER
# ============================================================

def send_logs(parsed_logs):
    """
    Send collected logs to the central AegisGuard Analyzer.
    """

    payload = {
        "machine_id": platform.node(),
        "hostname": platform.node(),
        "os": platform.platform(),
        "logs": parsed_logs
    }

    print("\nSending logs to Analyzer:")
    print(ANALYZER)

    try:
        response = requests.post(
            ANALYZER,
            json=payload,
            timeout=60
        )

        print(
            "Analyzer HTTP Status:",
            response.status_code
        )

        print(
            "Analyzer Response:",
            response.text
        )

        return response.status_code == 200

    except requests.RequestException as e:

        print(
            "Failed to connect to Analyzer:",
            e
        )

        return False


# ============================================================
# COLLECT WINDOWS SECURITY LOGS
# ============================================================

def collect_security_logs(
    hours=HOURS,
    max_events=MAX_EVENTS
):
    """
    Collect Windows Security logs.

    hours:
        Number of hours of historical events to collect.

    max_events:
        Maximum number of events to collect.
    """

    start_time = (
        datetime.now() - timedelta(hours=hours)
    ).strftime("%Y-%m-%dT%H:%M:%S")

    powershell_command = f"""
$start = (Get-Date).AddHours(-{hours})

Get-WinEvent -FilterHashtable @{{
    LogName='Security'
    StartTime=$start
}} -MaxEvents {max_events} |
Select-Object RecordId,
              Id,
              TimeCreated,
              MachineName,
              LevelDisplayName,
              Message |
ConvertTo-Json -Depth 4
"""

    print("\nStart Time:", start_time)

    print("\nPowerShell Command:")
    print(powershell_command)

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

    # --------------------------------------------------------
    # PowerShell error
    # --------------------------------------------------------

    if result.returncode != 0:

        print("\nPowerShell Error:")
        print(result.stderr)

        return []

    # --------------------------------------------------------
    # Empty output
    # --------------------------------------------------------

    if not result.stdout.strip():

        print(
            "\nNo Security events were returned."
        )

        return []

    # --------------------------------------------------------
    # Parse JSON
    # --------------------------------------------------------

    try:

        logs = json.loads(
            result.stdout
        )

        if isinstance(logs, dict):
            logs = [logs]

        print(
            f"\nSuccessfully parsed {len(logs)} Security events."
        )

        return logs

    except json.JSONDecodeError as e:

        print(
            "\nFailed to parse PowerShell JSON output."
        )

        print(
            "JSON error:",
            e
        )

        print(
            "\nRaw PowerShell output:"
        )

        print(
            result.stdout
        )

        return []


# ============================================================
# SAVE RAW LOGS
# ============================================================

def save_raw_logs(
    logs,
    filename=None
):
    """
    Save collected logs locally.
    """

    if filename is None:
        filename = config.get(
            "raw_output_file",
            "raw_security_logs.json"
        )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            logs,
            file,
            indent=4,
            default=str
        )

    print(
        f"Raw logs saved to '{filename}'"
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("            AEGISGUARD WINDOWS")
    print("            SECURITY COLLECTOR")
    print("=" * 60)

    print(
        f"\nAnalyzer URL : {ANALYZER}"
    )

    print(
        f"History Hours: {HOURS}"
    )

    print(
        f"Max Events   : {MAX_EVENTS}"
    )

    # --------------------------------------------------------
    # Historical collection
    # --------------------------------------------------------

    logs = collect_security_logs(
        hours=HOURS,
        max_events=MAX_EVENTS
    )

    print(
        f"\nCollected {len(logs)} Security Events.\n"
    )

    # --------------------------------------------------------
    # Process collected logs
    # --------------------------------------------------------

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
        success = send_logs(logs)

        if success:

            print(
                "\nLogs successfully uploaded to Analyzer."
            )

        else:

            print(
                "\nLogs were collected, "
                "but upload to Analyzer failed."
            )

    else:

        print(
            "No matching Security events found."
        )