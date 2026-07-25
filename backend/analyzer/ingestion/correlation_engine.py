import json
from datetime import datetime, timedelta
from collections import defaultdict

def run_correlation():

    try:
        from .mitre_mapper import get_mitre_mapping
    except ImportError:
        from backend.analyzer.ingestion.mitre_mapper import get_mitre_mapping

    try:
        from backend.analyzer.database import get_connection
    except ImportError:
        from database import get_connection

    # --------------------------
    # Configuration
    # --------------------------

    import os

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    ANALYZER_DIR = os.path.dirname(BASE_DIR) # backend/analyzer/output folder
    OUTPUT_DIR = os.path.join(ANALYZER_DIR, "output")

    INPUT_FILE = os.path.join(OUTPUT_DIR, "classified_logs.json")
    OUTPUT_FILE = os.path.join(OUTPUT_DIR, "incidents.json")
    TIME_WINDOW = timedelta(minutes=5)

    # --------------------------
    # Load classified logs
    # --------------------------

    with open(INPUT_FILE, "r") as f:
        logs = json.load(f)

    for log in logs:
        log["dt"] = datetime.fromisoformat(log["timestamp"].replace("Z", "+00:00"))

    logs.sort(key=lambda x: x["dt"])

    machines = defaultdict(list)

    for log in logs:
        machine = log.get("hostname", "unknown")
        machines[machine].append(log)

    incidents = []
    incident_counter = 1


    def create_incident(machine, attack, severity, score, related_logs):
        global incident_counter

        latest = related_logs[-1]

        ml_prediction = latest.get("ml_prediction", "UNKNOWN")
        ml_confidence = latest.get("ml_confidence", 0.0)
        mitre = get_mitre_mapping(ml_prediction)

        incidents.append({
            "incident_id": f"INC-{incident_counter:04d}",
            "machine_id": machine,
            "attack_type": attack,
            "severity": severity,
            "risk_score": score,
            "ml_prediction": ml_prediction,
            "ml_confidence": round(float(ml_confidence), 2),
            "mitre": mitre,

            # New fields
            "hostname": latest.get("hostname", machine),
            "os": latest.get("os", "Windows"),
            "source_ip": latest.get("source_ip", ""),
            "destination_ip": latest.get("destination_ip", ""),
            "user": latest.get("user", ""),
            "process": latest.get("process", ""),
            "file_path": latest.get("file_path", ""),
            "threat_category": latest.get("threat_category", "Unknown"),
            "detection_method": "Rule Correlation + ML",
            "start_time": related_logs[0]["timestamp"],
            "end_time": related_logs[-1]["timestamp"],
            "related_logs": [
                x["raw_log"] for x in related_logs
            ]
        })

        incident_counter += 1


    def save_incidents_to_db():

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM incidents")

        for incident in incidents:

            cursor.execute("""
            INSERT INTO incidents(
                incident_id,
                log_id,
                threat_type,
                hostname,
                os,
                source_ip,
                user,
                process,
                file_path,
                severity,
                timestamp,
                status,
                action_taken,
                command_executed,
                playbook_steps,
                incident_report,
                alert_status,
                mitre
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,

            (
                incident["incident_id"],
                "",
                incident["attack_type"],
                incident["hostname"],
                incident["os"],
                incident["source_ip"],
                incident["user"],
                incident["process"],
                incident["file_path"],
                incident["severity"],
                incident["start_time"],
                "OPEN",
                "",
                "",
                json.dumps([]),
                "",
                "Pending",
                json.dumps(incident["mitre"])
            ))

        conn.commit()

        conn.close()

    # =====================================================
    # Correlation Rules
    # =====================================================

    for machine, machine_logs in machines.items():

        machine_logs.sort(key=lambda x: x["dt"])

        # ---------------------------------------------------
        # Rule 1 : Multiple Failed Login Attempts
        # ---------------------------------------------------

        failed_groups = defaultdict(list)

        for log in machine_logs:

            if log["event_type"] in [
                "FAILED_LOGIN",
                "AUTHENTICATION_FAILURE"
            ]:

                key = (
                    log["user"],
                    log["source_ip"]
                )

                failed_groups[key].append(log)

        for key, failed_logs in failed_groups.items():

            if len(failed_logs) >= 2:

                create_incident(
                    machine,
                    "Multiple Failed Login Attempts",
                    "HIGH",
                    80,
                    failed_logs
                )

        # ---------------------------------------------------
        # Rule 2 : Failed Login -> Successful Login
        # ---------------------------------------------------

        for i in range(len(machine_logs)):

            current = machine_logs[i]

            if current["event_type"] != "SUCCESSFUL_LOGIN":
                continue

            previous_failed = []

            for j in range(i):

                if current["dt"] - machine_logs[j]["dt"] > TIME_WINDOW:
                    continue

                if machine_logs[j]["event_type"] in [
                    "FAILED_LOGIN",
                    "AUTHENTICATION_FAILURE"
                ]:
                    previous_failed.append(machine_logs[j])

            if len(previous_failed) >= 3:

                related = previous_failed + [current]

                create_incident(
                    machine,
                    "Possible Brute Force Attack",
                    "CRITICAL",
                    95,
                    related
                )

        # ---------------------------------------------------
        # Rule 3 : Successful Login -> sudo
        # ---------------------------------------------------

        for i in range(len(machine_logs)):

            current = machine_logs[i]

            if current["event_type"] != "SUCCESSFUL_LOGIN":
                continue

            for j in range(i + 1, len(machine_logs)):

                nxt = machine_logs[j]

                if nxt["dt"] - current["dt"] > TIME_WINDOW:
                    break

                if nxt["event_type"] == "SUDO_COMMAND":

                    create_incident(
                        machine,
                        "Privilege Escalation",
                        "CRITICAL",
                        90,
                        [current, nxt]
                    )

                    break

        # ---------------------------------------------------
        # Rule 4 : Multiple sudo commands
        # ---------------------------------------------------

        sudo_logs = [
            x for x in machine_logs
            if x["event_type"] == "SUDO_COMMAND"
        ]

        if len(sudo_logs) >= 5:

            create_incident(
                machine,
                "Suspicious Administrative Activity",
                "HIGH",
                75,
                sudo_logs
            )

    # -------------------------------------------------------
    # Save incidents
    # -------------------------------------------------------

    with open(OUTPUT_FILE, "w") as f:
        json.dump(incidents, f, indent=4)

    save_incidents_to_db()
    print(f"{len(incidents)} incidents generated.")

if __name__ == "__main__":
    run_correlation()