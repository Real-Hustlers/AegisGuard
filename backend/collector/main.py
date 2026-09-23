try:
    from backend.collector.collector import (
        collect_security_logs,
        save_raw_logs,
        send_logs,
    )
    from backend.collector.parser import parse_event
    from backend.collector.detector import detect_threat
    from backend.collector.config_loader import load_config
    from backend.collector.live_monitoring import start_live_monitor
except ImportError:
    from collector import (
        collect_security_logs,
        save_raw_logs,
        send_logs,
    )
    from parser import parse_event
    from detector import detect_threat
    from config_loader import load_config
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

    # Governed by S7-D/S7-F. Disabled unless explicitly opted in.
    save_raw_logs(raw_logs)

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