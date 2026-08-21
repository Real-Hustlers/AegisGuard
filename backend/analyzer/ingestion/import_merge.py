import os
import json
import sys


def get_app_base_dir():
    """
    Returns the writable application directory.

    Packaged EXE:
        Directory containing app.exe

    Source:
        Project root
    """

    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)

    # Current file:
    # backend/analyzer/ingestion/import_merge.py
    #
    # Go back 4 levels to project root.
    return os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(
                    os.path.abspath(__file__)
                )
            )
        )
    )


# =========================================================
# PATH CONFIGURATION
# =========================================================

BASE_DIR = get_app_base_dir()

INPUT_FILE = os.path.join(
    BASE_DIR,
    "data",
    "windows_logs.json"
)

OUTPUT_FOLDER = os.path.join(
    BASE_DIR,
    "output"
)

OUTPUT_FILE = "merged_logs.json"


# =========================================================
# ATOMIC JSON WRITER
# =========================================================

def atomic_json_write(path, data):
    """
    Write JSON safely using a temporary file,
    then atomically replace the destination.
    """

    temp_path = (
        str(path)
        +
        ".tmp"
    )

    try:

        with open(
            temp_path,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                indent=4,
                default=str
            )

            f.flush()

            os.fsync(
                f.fileno()
            )

        os.replace(
            temp_path,
            path
        )

    except Exception:

        try:

            if os.path.exists(
                temp_path
            ):

                os.remove(
                    temp_path
                )

        except Exception:

            pass

        raise


# =========================================================
# MERGE LOGS
# =========================================================

def merge_logs():

    all_logs = []

    os.makedirs(
        os.path.dirname(INPUT_FILE),
        exist_ok=True
    )

    os.makedirs(
        OUTPUT_FOLDER,
        exist_ok=True
    )

    print(
        f"Merge input file: {INPUT_FILE}",
        flush=True
    )

    print(
        f"Merge output folder: {OUTPUT_FOLDER}",
        flush=True
    )

    # =====================================================
    # CHECK INPUT FILE
    # =====================================================

    if not os.path.exists(
        INPUT_FILE
    ):

        print(
            f"Windows log file not found: "
            f"{INPUT_FILE}",
            flush=True
        )

        return

    # =====================================================
    # LOAD WINDOWS LOGS
    # =====================================================

    try:

        with open(
            INPUT_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

    except json.JSONDecodeError as e:

        print(
            f"Invalid JSON in "
            f"{INPUT_FILE}: {e}",
            flush=True
        )

        return

    except Exception as e:

        print(
            f"Error reading "
            f"{INPUT_FILE}: {e}",
            flush=True
        )

        return

    # =====================================================
    # DETECT JSON FORMAT
    # =====================================================

    machine_id = "UNKNOWN"
    hostname = "UNKNOWN"
    operating_system = "Windows"

    if isinstance(
        data,
        list
    ):

        logs = data

    elif isinstance(
        data,
        dict
    ):

        machine_id = data.get(
            "machine_id",
            "UNKNOWN"
        )

        hostname = data.get(
            "hostname",
            "UNKNOWN"
        )

        operating_system = data.get(
            "os",
            "Windows"
        )

        logs = data.get(
            "logs",
            []
        )

    else:

        print(
            "Unsupported windows_logs.json format.",
            flush=True
        )

        return

    if not isinstance(
        logs,
        list
    ):

        print(
            "Invalid logs format. Expected a list.",
            flush=True
        )

        return

    print(
        f"Collected logs loaded: "
        f"{len(logs)}",
        flush=True
    )

    # =====================================================
    # NORMALIZE EACH LOG
    # =====================================================

    for index, log in enumerate(
        logs,
        start=1
    ):

        if not isinstance(
            log,
            dict
        ):

            continue

        timestamp = (
            log.get("timestamp")
            or
            log.get("TimeCreated")
        )

        event_type = (
            log.get("event_type")
            or
            log.get("event_id")
            or
            log.get("Id")
        )

        raw_log = (
            log.get("raw_log")
            or
            log.get("Message")
            or
            ""
        )

        severity = (
            log.get("severity")
            or
            log.get("LevelDisplayName")
            or
            "INFO"
        )

        merged_log = {

            "log_id":
                f"LOG-{index:06d}",

            "machine_id":
                (
                    log.get(
                        "machine_id"
                    )
                    or
                    machine_id
                ),

            "hostname":
                (
                    log.get(
                        "hostname"
                    )
                    or
                    log.get(
                        "MachineName"
                    )
                    or
                    hostname
                ),

            "os":
                (
                    log.get(
                        "os"
                    )
                    or
                    operating_system
                ),

            "timestamp":
                timestamp,

            "event_type":
                event_type,

            "user":
                (
                    log.get(
                        "user"
                    )
                    or
                    log.get(
                        "User"
                    )
                ),

            "source_ip":
                (
                    log.get(
                        "source_ip"
                    )
                    or
                    log.get(
                        "SourceIp"
                    )
                ),

            "destination_ip":
                (
                    log.get(
                        "destination_ip"
                    )
                    or
                    log.get(
                        "DestinationIp"
                    )
                ),

            "process":
                (
                    log.get(
                        "process"
                    )
                    or
                    log.get(
                        "ProcessName"
                    )
                ),

            "file_path":
                (
                    log.get(
                        "file_path"
                    )
                    or
                    log.get(
                        "FilePath"
                    )
                ),

            "severity":
                severity,

            "raw_log":
                raw_log,

            "record_id":
                (
                    log.get(
                        "record_id"
                    )
                    or
                    log.get(
                        "RecordId"
                    )
                ),

            "event_id":
                (
                    log.get(
                        "event_id"
                    )
                    or
                    log.get(
                        "Id"
                    )
                ),
        }

        all_logs.append(
            merged_log
        )

    # =====================================================
    # SORT LOGS
    # =====================================================

    all_logs.sort(
        key=lambda x: str(
            x.get(
                "timestamp"
            )
            or
            ""
        )
    )

    # =====================================================
    # SAVE MERGED LOGS ATOMICALLY
    # =====================================================

    output_path = os.path.join(
        OUTPUT_FOLDER,
        OUTPUT_FILE
    )

    try:

        atomic_json_write(
            output_path,
            all_logs
        )

    except Exception as e:

        print(
            f"Error saving merged logs: {e}",
            flush=True
        )

        return

    # =====================================================
    # RESULT
    # =====================================================

    print(
        f"Total Logs : "
        f"{len(all_logs)}",
        flush=True
    )

    print(
        f"Saved to : "
        f"{output_path}",
        flush=True
    )


# =========================================================
# DIRECT EXECUTION
# =========================================================

if __name__ == "__main__":
    merge_logs()