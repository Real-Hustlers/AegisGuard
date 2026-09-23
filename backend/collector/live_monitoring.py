import json
import platform
import requests
import time
import subprocess

from backend.collector.parser import parse_event
from backend.collector.detector import detect_threat
from backend.collector.config_loader import get_config_path, load_config
from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.diagnostics import (
    sanitize_diagnostic,
    sanitize_http_response,
    sanitize_url_for_diagnostics,
)


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


def get_heartbeat_interval_seconds(config=None):
    source = CONFIG if config is None else config
    value = source.get(
        "collector_heartbeat_interval_seconds",
        30,
    )
    try:
        interval = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "collector_heartbeat_interval_seconds must be numeric"
        ) from exc
    if interval <= 0:
        raise ValueError(
            "collector_heartbeat_interval_seconds must be greater than zero"
        )
    return interval


def _heartbeat_enabled(runtime):
    heartbeat_url = getattr(runtime, "heartbeat_url", None)
    return (
        getattr(runtime, "auth_required", False) is True
        and isinstance(heartbeat_url, str)
        and bool(heartbeat_url.strip())
    )


def maybe_send_heartbeat(
    runtime,
    next_heartbeat_at,
    interval_seconds,
    *,
    now=None,
):
    """Attempt one scheduled heartbeat without owning durable log state."""

    if not _heartbeat_enabled(runtime):
        return next_heartbeat_at, False

    now_value = (
        time.monotonic()
        if now is None
        else float(now)
    )
    due_at = (
        0.0
        if next_heartbeat_at is None
        else float(next_heartbeat_at)
    )
    if now_value < due_at:
        return due_at, False

    next_due = now_value + float(interval_seconds)

    try:
        body = runtime.heartbeat()
    except (
        requests.RequestException,
        ValueError,
        KeyError,
        TypeError,
    ) as exc:
        print(
            "[HEARTBEAT FAILED] "
            f"{sanitize_diagnostic(exc)}. "
            "Collection and durable delivery continue."
        )
        return next_due, False

    print(
        "[HEARTBEAT OK] "
        f"collector={body.get('collector_id', runtime.collector_id)} "
        f"last_heartbeat_at={body.get('last_heartbeat_at')}"
    )
    return next_due, True


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
                        sanitize_diagnostic(response_data),
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
                    sanitize_http_response(response),
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
                sanitize_http_response(response),
            )

        except requests.ConnectTimeout:

            print(
                "[UPLOAD CONNECT TIMEOUT] "
                f"Could not establish a connection within {UPLOAD_TIMEOUT} seconds."
            )

        except requests.ReadTimeout:

            print(
                "[UPLOAD READ TIMEOUT] "
                f"Analyzer accepted the connection but did not respond within {UPLOAD_TIMEOUT} seconds."
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
                "Analyzer URL:",
                sanitize_url_for_diagnostics(ANALYZER),
            )

            print(
                "Error:",
                sanitize_diagnostic(e),
            )

        except requests.RequestException as e:

            print(
                "[UPLOAD ERROR]",
                sanitize_diagnostic(e),
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
            sanitize_diagnostic(e),
        )

        return None

    except Exception as e:

        print(
            "PowerShell execution failed:",
            sanitize_diagnostic(e),
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

    if result.stderr:
        print(
            "PowerShell stderr:"
        )

        print(
            sanitize_diagnostic(result.stderr)
        )

    if result.returncode != 0:
        error_text = (result.stderr or "").lower()
        if any(token in error_text for token in (
            "unauthorized", "access is denied", "access denied", "permission"
        )):
            raise PermissionError(
                "AegisGuard Collector requires Administrator privileges to read "
                "the Windows Security Event Log."
            )
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
            sanitize_diagnostic(e),
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

    event_predicate = " or ".join(
        f"EventID={int(event_id)}"
        for event_id in EVENT_IDS
    )

    cmd = f"""
$filter = "*[System[(EventRecordID > {int(last_record_id)}) and ({event_predicate})]]"

$events = Get-WinEvent -LogName Security `
    -FilterXPath $filter `
    -Oldest `
    -MaxEvents 100

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
            sanitize_diagnostic(result.stderr)
        )

        error_text = (result.stderr or "").lower()
        if any(token in error_text for token in (
            "unauthorized", "access is denied", "access denied", "permission"
        )):
            raise PermissionError(
                "AegisGuard Collector requires Administrator privileges to read "
                "the Windows Security Event Log."
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
            sanitize_diagnostic(e),
        )

        print(
            "Raw PowerShell output omitted because it may "
            "contain Windows Security event data."
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
    last_record=None,
    runtime=None,
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

    if runtime is None:
        runtime = DurableCollectorRuntime.from_config(
            CONFIG,
            get_config_path(),
            hostname=platform.node(),
            os_name=platform.platform(),
        )

    print(
        "Analyzer URL:",
        sanitize_url_for_diagnostics(
            runtime.analyzer_url
        ),
    )

    print("Collector hostname:", platform.node())
    print("Collector ID:", runtime.collector_id)
    print("Collector state:", runtime.state.path)
    print("Config path:", get_config_path())

    if (
        "127.0.0.1" in runtime.analyzer_url
        or "localhost" in runtime.analyzer_url.lower()
    ):
        print(
            "[WARNING] Analyzer URL is localhost. This only works when the "
            "Analyzer runs on this same PC; set collector_ingest_url in "
            "config.json for a remote Analyzer."
        )

    # --------------------------------------------------------
    # Determine restart-safe collection cursor
    # --------------------------------------------------------

    last_record = runtime.initialize(
        last_record,
        get_latest_record_id,
    )

    print(
        "Starting from RecordID:",
        last_record
    )

    print(
        "Last ACKed RecordID:",
        runtime.checkpoint()
    )

    heartbeat_interval = get_heartbeat_interval_seconds()
    next_heartbeat_at = 0.0

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
                sanitize_diagnostic(e),
            )

            time.sleep(
                2
            )

            continue

        # No new events. Pending durable batches still need delivery.
        if not events:

            runtime.flush_pending()
            last_record = runtime.collection_cursor()

            next_heartbeat_at, _heartbeat_sent = maybe_send_heartbeat(
                runtime,
                next_heartbeat_at,
                heartbeat_interval,
            )

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
                    f"{parsed.get('event_type', 'UNKNOWN')}"
                )

            except Exception as e:

                print(
                    "[ERROR] Failed to process event:",
                    sanitize_diagnostic(e),
                )

        # ====================================================
        # DURABLY SPOOL, THEN ATTEMPT DELIVERY
        # ====================================================

        if parsed_batch:

            batch_id = runtime.enqueue_logs(
                parsed_batch,
                batch_record_ids,
            )

            print(
                f"[SPOOL] batch={batch_id} "
                f"logs={len(parsed_batch)} "
                f"max_record_id={max(batch_record_ids)}"
            )

            upload_success = runtime.flush_pending()

            # Collection advances to the highest locally durable RecordID,
            # even when the network is down. The ACK checkpoint itself only
            # advances after an exact server durable acknowledgement.
            last_record = runtime.collection_cursor()

            print(
                "Collection cursor:",
                last_record
            )

            print(
                "Last ACKed RecordID:",
                runtime.checkpoint()
            )

            if upload_success:

                print(
                    f"[Analyzer] Durable batch delivery successful "
                    f"({len(parsed_batch)} logs)"
                )

            else:

                print(
                    "[Analyzer] Batch remains durably spooled. "
                    "Collection will continue and delivery will retry "
                    "on the next polling cycle."
                )

        next_heartbeat_at, _heartbeat_sent = maybe_send_heartbeat(
            runtime,
            next_heartbeat_at,
            heartbeat_interval,
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

    except PermissionError as e:

        print(
            sanitize_diagnostic(e)
        )

    except KeyboardInterrupt:

        print()

        print(
            "AegisGuard Collector stopped."
        )
