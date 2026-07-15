import json
from datetime import datetime
from collections import defaultdict

# Base threat score for each event type
BASE_SCORES = {
    "SUCCESSFUL_LOGIN": 5,
    "FAILED_LOGIN": 25,
    "SUDO_EXECUTED": 60,
    "PRIVILEGE_ESCALATION": 80,
    "USB_CONNECTED": 35,
    "FILE_MODIFIED": 15,
    "FILE_DELETED": 50,
    "DEFENDER_ALERT": 95
}

# Threat category mapping
CATEGORIES = {
    "SUCCESSFUL_LOGIN": "Authentication",
    "FAILED_LOGIN": "Authentication",
    "SUDO_EXECUTED": "Privilege Escalation",
    "PRIVILEGE_ESCALATION": "Privilege Escalation",
    "USB_CONNECTED": "Device Activity",
    "FILE_MODIFIED": "File Activity",
    "FILE_DELETED": "File Activity",
    "DEFENDER_ALERT": "Malware"
}

failed_attempts = defaultdict(int)


def calculate_score(log):
    score = BASE_SCORES.get(log["event_type"], 10)

    # Administrator / root accounts
    if log["user"].lower() in ["administrator", "admin", "root"]:
        score += 20

    # Night-time activity (10 PM - 6 AM)
    try:
        hour = datetime.fromisoformat(
            log["timestamp"].replace("Z", "+00:00")
        ).hour

        if hour >= 22 or hour < 6:
            score += 15
    except:
        pass

    # Failed login tracking
    if log["event_type"] == "FAILED_LOGIN":
        ip = log["source_ip"]
        failed_attempts[ip] += 1

        if failed_attempts[ip] >= 5:
            score += 20

    # Successful login after repeated failures
    if log["event_type"] == "SUCCESSFUL_LOGIN":
        ip = log["source_ip"]

        if failed_attempts[ip] >= 3:
            score += 15

    return min(score, 100)


def get_level(score):
    if score <= 20:
        return "LOW"
    elif score <= 40:
        return "MEDIUM"
    elif score <= 70:
        return "HIGH"
    else:
        return "CRITICAL"


def classify_logs(input_file, output_file):
    with open(input_file, "r") as f:
        logs = json.load(f)

    classified_logs = []

    for log in logs:
        score = calculate_score(log)

        log["threat_category"] = CATEGORIES.get(
            log["event_type"], "Unknown"
        )

        log["threat_score"] = score
        log["threat_level"] = get_level(score)

        classified_logs.append(log)

    with open(output_file, "w") as f:
        json.dump(classified_logs, f, indent=4)

    print(f"Classified {len(classified_logs)} logs.")
    print(f"Saved to {output_file}")


if __name__ == "__main__":
    classify_logs(
        "./output/merged_logs.json",
        "./output/classified_logs.json"
    )