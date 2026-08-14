import os
import json
from glob import glob
import sys


def get_app_base_dir():
    """
    Returns the writable application directory.

    Packaged EXE:
        C:\\Users\\saran\\makethon\\dist

    Source:
        C:\\Users\\saran\\makethon
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)

    # import_merge.py is:
    # backend/analyzer/ingestion/import_merge.py
    #
    # parents:
    # 0 = ingestion
    # 1 = analyzer
    # 2 = backend
    # 3 = project root
    return os.path.dirname(
        os.path.dirname(
            os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))
            )
        )
    )


BASE_DIR = get_app_base_dir()

INPUT_FOLDER = os.path.join(BASE_DIR, "test")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "output")
OUTPUT_FILE = "merged_logs.json"


def merge_logs():

    all_logs = []
    log_counter = 1

    os.makedirs(INPUT_FOLDER, exist_ok=True)
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

    print(f"Merge input folder: {INPUT_FOLDER}", flush=True)
    print(f"Merge output folder: {OUTPUT_FOLDER}", flush=True)

    json_files = glob(
        os.path.join(INPUT_FOLDER, "*.json")
    )

    if not json_files:
        print("No machine JSON files found.", flush=True)
        return

    for file in json_files:

        try:

            with open(
                file,
                "r",
                encoding="utf-8"
            ) as f:

                machine = json.load(f)

            machine_id = machine.get(
                "machine_id",
                "UNKNOWN"
            )

            hostname = machine.get(
                "hostname",
                "UNKNOWN"
            )

            operating_system = machine.get(
                "os",
                "UNKNOWN"
            )

            logs = machine.get(
                "logs",
                []
            )

            for log in logs:

                # -----------------------------------------
                # Support both normalized logs and raw
                # Windows Event logs
                # -----------------------------------------

                timestamp = (
                    log.get("timestamp")
                    or log.get("TimeCreated")
                )

                event_type = (
                    log.get("event_type")
                    or log.get("Id")
                )

                raw_log = (
                    log.get("raw_log")
                    or log.get("Message")
                )

                severity = (
                    log.get("severity")
                    or log.get("LevelDisplayName")
                )

                merged_log = {
                    "log_id": f"LOG-{log_counter:06d}",

                    "machine_id": machine_id,

                    "hostname": (
                        log.get("hostname")
                        or log.get("MachineName")
                        or hostname
                    ),

                    "os": operating_system,

                    "timestamp": timestamp,

                    "event_type": event_type,

                    "user": log.get("user"),

                    "source_ip": log.get("source_ip"),

                    "destination_ip": log.get(
                        "destination_ip"
                    ),

                    "process": log.get(
                        "process"
                    ),

                    "file_path": log.get(
                        "file_path"
                    ),

                    "severity": severity,

                    "raw_log": raw_log,

                    # Keep original Windows event identifiers
                    "record_id": log.get(
                        "RecordId"
                    ),

                    "event_id": log.get(
                        "Id"
                    )
                }

                all_logs.append(
                    merged_log
                )

                log_counter += 1

        except Exception as e:

            print(
                f"Error reading {file}: {e}",
                flush=True
            )

    # -----------------------------------------
    # Sort chronologically
    # -----------------------------------------

    all_logs.sort(
        key=lambda x: str(
            x.get("timestamp") or ""
        )
    )

    output_path = os.path.join(
        OUTPUT_FOLDER,
        OUTPUT_FILE
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            all_logs,
            f,
            indent=4,
            default=str
        )

    print(
        f"Merged {len(json_files)} machine files",
        flush=True
    )

    print(
        f"Total Logs : {len(all_logs)}",
        flush=True
    )

    print(
        f"Saved to : {output_path}",
        flush=True
    )


if __name__ == "__main__":
    merge_logs()