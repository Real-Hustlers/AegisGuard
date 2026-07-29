import json

from collector import collect_security_logs, send_logs
from parser import parse_event
from detector import detect_threat
from config_loader import load_config

# NEW
from live_monitoring import start_live_monitor


def main():

    print("=" * 60)
    print("Windows Security Log Collector")
    print("=" * 60)

    config = load_config()

    print("Configuration Loaded Successfully\n")

    # -------------------------
    # Import Historical Logs
    # -------------------------
    raw_logs = collect_security_logs(
        hours=config["hours"],
        max_events=config["max_events"]
    )

    print(f"Collected {len(raw_logs)} Security Events.\n")

    with open(config["raw_output_file"], "w", encoding="utf-8") as file:
        json.dump(raw_logs, file, indent=4, default=str)

    parsed_logs = []

    for event in raw_logs:

        parsed = parse_event(event)
        parsed["threat_level"] = detect_threat(parsed)

        parsed_logs.append(parsed)

    # Upload historical logs once
    send_logs(parsed_logs)

    # Find highest RecordId imported
    if raw_logs:
        last_record = max(
            event["RecordId"]
            for event in raw_logs
        )
    else:
        last_record = 0

    print("=" * 60)
    print(f"Imported {len(parsed_logs)} historical logs.")
    print("Starting Live Monitoring...")
    print("=" * 60)

    # Start monitoring only NEW events
    start_live_monitor(last_record)


if __name__ == "__main__":
    main()