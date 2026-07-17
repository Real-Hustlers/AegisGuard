import json

from collector import collect_security_logs
from parser import parse_event
from detector import detect_threat
from config_loader import load_config


def main():

    print("=" * 60)
    print("Windows Security Log Collector")
    print("=" * 60)

    # Load configuration
    config = load_config()

    print("Configuration Loaded Successfully\n")

    # Collect Security Logs
    raw_logs = collect_security_logs(
        hours=config["hours"],
        max_events=config["max_events"]
    )

    print(f"Collected {len(raw_logs)} Security Events.\n")

    # Save Raw Logs
    with open(config["raw_output_file"], "w", encoding="utf-8") as file:
        json.dump(raw_logs, file, indent=4, default=str)

    print(f"Raw logs saved to '{config['raw_output_file']}'\n")

    parsed_logs = []

    # Parse each event
    for event in raw_logs:

        parsed = parse_event(event)

        # Detect threat level
        parsed["threat_level"] = detect_threat(parsed)

        parsed_logs.append(parsed)

    # Save Parsed Logs
    with open(config["output_file"], "w", encoding="utf-8") as file:
        json.dump(parsed_logs, file, indent=4)

    print("=" * 60)
    print("Windows Log Collection Completed Successfully")
    print("=" * 60)

    print(f"Total Raw Events      : {len(raw_logs)}")
    print(f"Total Parsed Events   : {len(parsed_logs)}")
    print(f"Raw Output File       : {config['raw_output_file']}")
    print(f"Parsed Output File    : {config['output_file']}")


if __name__ == "__main__":
    main()