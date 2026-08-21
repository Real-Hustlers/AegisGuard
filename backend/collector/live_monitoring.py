import json
import platform
import requests
import time
import subprocess

from backend.collector.parser import parse_event
from backend.collector.detector import detect_threat
from backend.collector.config_loader import load_config


# ============================================================
# CONFIGURATION
# ============================================================

CONFIG = load_config()

ANALYZER = CONFIG["analyzer_url"]
EVENT_IDS = CONFIG["event_ids"]

POWERSHELL_TIMEOUT = 30

UPLOAD_TIMEOUT = 30
UPLOAD_RETRIES = 3
RETRY_DELAY = 2


# ============================================================
# SEND BATCH OF LOGS TO ANALYZER
# ============================================================

def send_logs(parsed_logs):
    """
    Send multiple parsed Windows events in one HTTP request.

    Returns:
        True  -> Analyzer accepted the batch
        False -> Upload failed
    """

    if not parsed_logs:
        return True

    payload = {
        "machine_id": platform.node(),
        "hostname": platform.node(),
        "os": platform.platform(),
        "logs": parsed_logs
    }

    for attempt in range(
        1,
        UPLOAD_RETRIES + 1
    ):

        try:

            print(
                f"[Analyzer] Uploading batch of "
                f"{len(parsed_logs)} logs "
                f"(attempt {attempt}/{UPLOAD_RETRIES})"
            )

            response = requests.post(
                ANALYZER,
                json=payload,
                timeout=UPLOAD_TIMEOUT
            )

            # ------------------------------------------------
            # SUCCESS
            # ------------------------------------------------

            if 200 <= response.status_code < 300:

                print(
                    f"[UPLOAD SUCCESS] "
                    f"HTTP {response.status_code}"
                )

                try:

                    response_data = response.json()

                    print(
                        "[Analyzer Response]",
                        response_data
                    )

                except ValueError:
                    pass

                return True

            # ------------------------------------------------
            # CLIENT ERROR
            # ------------------------------------------------

            if 400 <= response.status_code < 500:

                print(
                    f"[UPLOAD REJECTED] "
                    f"HTTP {response.status_code}"
                )

                print(
                    "Analyzer response:",
                    response.text
                )

                return False

            # ------------------------------------------------
            # SERVER ERROR
            # ------------------------------------------------

            print(
                f"[ANALYZER ERROR] "
                f"HTTP {response.status_code}"
            )

            print(
                "Analyzer response:",
                response.text
            )

        except requests.Timeout:

            print(
                "[UPLOAD TIMEOUT] "
                f"Analyzer did not respond within "
                f"{UPLOAD_TIMEOUT} seconds."
            )

        except requests.ConnectionError as e:

            print(
                "[ANALYZER OFFLINE] "
                "Unable to connect to Analyzer."
            )

            print(
                f"Analyzer URL: {ANALYZER}"
            )

            print(
                f"Error: {e}"
            )

        except requests.RequestException as e:

            print(
                "[UPLOAD ERROR]",
                e
            )

        if attempt < UPLOAD_RETRIES:

            print(
                f"[Analyzer] Retrying in "
                f"{RETRY_DELAY} seconds..."
            )

            time.sleep(
                RETRY_DELAY
            )

    print(
        "[UPLOAD FAILED] "
        "Analyzer could not receive the batch "
        "after all retries."
    )

    return False


# ============================================================
# RUN POWERSHELL COMMAND
# ============================================================

def _run_powershell(cmd):

    try:

        return subprocess.run(
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
            errors="ignore",
            timeout=POWERSHELL_TIMEOUT
        )

    except subprocess.TimeoutExpired as e:

        print(
            "PowerShell timed out:",
            e
        )

        return None

    except Exception as e:

        print(
            "PowerShell execution failed:",
            e
        )

        return None


# ============================================================
# GET LATEST WINDOWS SECURITY RECORD ID
# ============================================================

def get_latest_record_id():

    cmd = r"""
Get-WinEvent -LogName Security -MaxEvents 1 |
Select-Object RecordId |
ConvertTo-Json
"""

    result = _run_powershell(
        cmd
    )

    if result is None:
        return 0

    print(
        "PowerShell stdout:"
    )

    print(
        result.stdout
    )

    print(
        "PowerShell stderr:"
    )

    print(
        result.stderr
    )

    if result.returncode != 0:
        return 0

    if not result.stdout.strip():
        return 0

    try:

        obj = json.loads(
            result.stdout
        )

    except json.JSONDecodeError as e:

        print(
            "Failed to parse latest RecordId JSON:",
            e
        )

        return 0

    if isinstance(
        obj,
        list
    ):

        if not obj:
            return 0

        obj = obj[0]

    if not isinstance(
        obj,
        dict
    ):

        return 0

    record_id = obj.get(
        "RecordId",
        obj.get(
            "record_id",
            0
        )
    )

    try:

        return int(
            record_id
        )

    except (
        TypeError,
        ValueError
    ):

        return 0


# ============================================================
# COLLECT NEW WINDOWS SECURITY EVENTS
# ============================================================

def collect_new_events(
    last_record_id
):

    ids = ",".join(
        str(i)
        for i in EVENT_IDS
    )

    cmd = f"""
$events = Get-WinEvent -FilterHashtable @{{
    LogName = 'Security'
    Id = @({ids})
}} -MaxEvents 100 |
Where-Object {{
    $_.RecordId -gt {last_record_id}
}} |
Sort-Object RecordId

$events |
Select-Object RecordId,
              Id,
              TimeCreated,
              MachineName,
              LevelDisplayName,
              Message |
ConvertTo-Json -Depth 4
"""

    result = _run_powershell(
        cmd
    )

    if result is None:
        return []

    if result.returncode != 0:

        print(
            "PowerShell stderr:"
        )

        print(
            result.stderr
        )

        return []

    if not result.stdout.strip():
        return []

    try:

        logs = json.loads(
            result.stdout
        )

    except json.JSONDecodeError as e:

        print(
            "Failed to parse PowerShell JSON:",
            e
        )

        print(
            result.stdout
        )

        return []

    if isinstance(
        logs,
        dict
    ):

        logs = [
            logs
        ]

    if not isinstance(
        logs,
        list
    ):

        return []

    return logs


# ============================================================
# START LIVE MONITOR
# ============================================================

def start_live_monitor(
    last_record=None
):

    print(
        "=" * 60
    )

    print(
        "Live Windows Security Monitor Started"
    )

    print(
        "=" * 60
    )

    print(
        "Analyzer URL:",
        ANALYZER
    )

    # --------------------------------------------------------
    # Determine initial RecordID
    # --------------------------------------------------------

    if last_record is None:

        last_record = (
            get_latest_record_id()
        )

    print(
        "Starting from RecordID:",
        last_record
    )

    # --------------------------------------------------------
    # Continuous monitoring loop
    # --------------------------------------------------------

    while True:

        try:

            events = collect_new_events(
                last_record
            )

        except Exception as e:

            print(
                "[ERROR] Event collection failed:",
                e
            )

            time.sleep(
                2
            )

            continue

        # No new events
        if not events:

            time.sleep(
                2
            )

            continue

        # ====================================================
        # BUILD ONE BATCH
        # ====================================================

        parsed_batch = []

        batch_record_ids = []

        for event in events:

            try:

                if not isinstance(
                    event,
                    dict
                ):

                    continue

                # --------------------------------------------
                # Parse event
                # --------------------------------------------

                parsed = parse_event(
                    event
                )

                if not isinstance(
                    parsed,
                    dict
                ):

                    print(
                        "[WARNING] Parser returned "
                        "invalid event."
                    )

                    continue

                # --------------------------------------------
                # RecordID
                # --------------------------------------------

                record_id = event.get(
                    "RecordId",
                    event.get(
                        "record_id"
                    )
                )

                if record_id is None:
                    continue

                try:

                    record_id = int(
                        record_id
                    )

                except (
                    TypeError,
                    ValueError
                ):

                    continue

                parsed[
                    "record_id"
                ] = record_id

                # --------------------------------------------
                # Threat detection
                # --------------------------------------------

                parsed[
                    "threat_level"
                ] = detect_threat(
                    parsed
                )

                # --------------------------------------------
                # Add to batch
                # --------------------------------------------

                parsed_batch.append(
                    parsed
                )

                batch_record_ids.append(
                    record_id
                )

                print(
                    f"[+] {record_id} "
                    f"{parsed.get('event_type', 'UNKNOWN')} "
                    f"{parsed.get('user', 'UNKNOWN')}"
                )

            except Exception as e:

                print(
                    "[ERROR] Failed to process event:",
                    e
                )

        # ====================================================
        # SEND ENTIRE BATCH ONCE
        # ====================================================

        if parsed_batch:

            upload_success = send_logs(
                parsed_batch
            )

            if upload_success:

                # --------------------------------------------
                # Move monitoring position forward only
                # after Analyzer accepted the batch.
                # --------------------------------------------

                last_record = max(
                    last_record,
                    max(
                        batch_record_ids
                    )
                )

                print(
                    "Last RecordID:",
                    last_record
                )

                print(
                    f"[Analyzer] Batch upload successful "
                    f"({len(parsed_batch)} logs)"
                )

            else:

                print(
                    "[Analyzer] Batch upload failed."
                )

                print(
                    "RecordID was not advanced. "
                    "Events will be retried on the "
                    "next polling cycle."
                )

        # ----------------------------------------------------
        # Wait before next polling cycle
        # ----------------------------------------------------

        time.sleep(
            2
        )


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        start_live_monitor()

    except KeyboardInterrupt:

        print()

        print(
            "AegisGuard Collector stopped."
        )