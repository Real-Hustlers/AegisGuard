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
    RESPONSE_DIR = os.path.join(OUTPUT_DIR, "response")
    os.makedirs(RESPONSE_DIR, exist_ok=True)
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
        nonlocal incident_counter
        latest = related_logs[-1]

        ml_prediction = latest.get("ml_prediction", "UNKNOWN")
        ml_confidence = latest.get("ml_confidence", 0.0)
        mitre = get_mitre_mapping(ml_prediction)
        for inc in incidents:
            if (
                inc["attack_type"] == attack and
                inc["hostname"] == latest.get("hostname", machine)
            ):
                return

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
    

    def generate_response_json(incident):

        data = {
            "incident_id": incident["incident_id"],
            "attack_type": incident["attack_type"],
            "severity": incident["severity"],
            "risk_score": incident["risk_score"],
            "mitre": incident["mitre"],

            "timeline": {
                "start_time": incident["start_time"],
                "end_time": incident["end_time"],
                "related_logs": incident["related_logs"]
            },

            "playbook": [
                "Investigate Incident",
                "Contain Threat",
                "Notify Administrator",
                "Generate Report"
            ],
            "commands": [
                "Simulated response executed",
                "Incident recorded",
                "Administrator notified"
            ],

            "status": "SIMULATED",

            "generated_at": datetime.now().isoformat()
        }

        filename = os.path.join(
            RESPONSE_DIR,
            f"incident_{incident['incident_id']}.json"
        )

        with open(filename, "w") as f:
            json.dump(data, f, indent=4)


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
                json.dumps(incident, indent=4),
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
        # Rule 1 : Brute Force Attack Detection
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

            # ---------------------------------------
            # Stage A
            # Multiple failed logins
            # ---------------------------------------

            if len(failed_logs) >= 3:

                create_incident(
                    machine,
                    "Multiple Failed Login Attempts",
                    "HIGH",
                    80,
                    failed_logs
                )

            # ---------------------------------------
            # Stage B
            # Failed logins followed by success
            # ---------------------------------------

            last_failed = failed_logs[-1]

            for log in machine_logs:

                if log["event_type"] != "SUCCESSFUL_LOGIN":
                    continue

                if log["user"] != last_failed["user"]:
                    continue

                if (
                    log["dt"] >= last_failed["dt"]
                    and
                    log["dt"] - last_failed["dt"] <= TIME_WINDOW
                ):

                    related = failed_logs + [log]

                    create_incident(
                        machine,
                        "Possible Brute Force Attack",
                        "CRITICAL",
                        95,
                        related
                    )

                    break

        # ---------------------------------------------------
        # Rule 2 : Privilege Escalation Detection
        # ---------------------------------------------------

        sudo_logs = []

        for i in range(len(machine_logs)):

            current = machine_logs[i]

            # ---------------------------------------
            # Stage A
            # Login followed by sudo
            # ---------------------------------------

            if current["event_type"] == "SUCCESSFUL_LOGIN":

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

                        sudo_logs.append(nxt)

                        break

            # Collect every sudo command
            if current["event_type"] == "SUDO_COMMAND":
                sudo_logs.append(current)

        # ---------------------------------------
        # Stage B
        # Excessive administrative activity
        # ---------------------------------------

        if len(sudo_logs) >= 5:

            create_incident(
                machine,
                "Suspicious Administrative Activity",
                "HIGH",
                75,
                sudo_logs
            )

        # ---------------------------------------------------
        # Rule 3 : Malware Execution Detection
        # ---------------------------------------------------

        for i in range(len(machine_logs)):

            current = machine_logs[i]

            if current["event_type"] != "PROCESS_CREATED":
                continue

            for j in range(i + 1, len(machine_logs)):

                nxt = machine_logs[j]

                if nxt["dt"] - current["dt"] > TIME_WINDOW:
                    break

                if nxt["event_type"] == "NETWORK_CONNECTION":

                    process_name = str(
                        current.get("process", "")
                    ).lower()

                    suspicious_processes = [
                        "powershell",
                        "cmd.exe",
                        "wscript",
                        "cscript",
                        "rundll32",
                        "mshta"
                    ]

                    if any(
                        proc in process_name
                        for proc in suspicious_processes
                    ):

                        create_incident(
                            machine,
                            "Possible Malware Execution",
                            "CRITICAL",
                            95,
                            [current, nxt]
                        )

                        break

        # ---------------------------------------------------
        # Rule 4 : Reconnaissance Detection
        # ---------------------------------------------------

        for i in range(len(machine_logs)):

            current = machine_logs[i]

            if current["event_type"] != "LOCAL_GROUP_ENUMERATION":
                continue

            related = [current]

            process_found = False
            network_found = False

            for j in range(i + 1, len(machine_logs)):

                nxt = machine_logs[j]

                if nxt["dt"] - current["dt"] > TIME_WINDOW:
                    break

                if (
                    not process_found
                    and
                    nxt["event_type"] == "PROCESS_CREATED"
                ):

                    process_found = True
                    related.append(nxt)

                elif (
                    process_found
                    and
                    nxt["event_type"] == "NETWORK_CONNECTION"
                ):

                    network_found = True
                    related.append(nxt)
                    break

            if process_found and network_found:

                create_incident(
                    machine,
                    "Reconnaissance Activity",
                    "HIGH",
                    75,
                    related
                )

        # ---------------------------------------------------
        # Rule 5 : Lateral Movement Detection
        # ---------------------------------------------------

        for i in range(len(machine_logs)):

            current = machine_logs[i]

            if current["event_type"] != "LOGON_SUCCESS":
                continue

            related = [current]

            network_found = False
            process_found = False

            for j in range(i + 1, len(machine_logs)):

                nxt = machine_logs[j]

                if nxt["dt"] - current["dt"] > TIME_WINDOW:
                    break

                if (
                    not network_found
                    and
                    nxt["event_type"] == "NETWORK_CONNECTION"
                ):

                    network_found = True
                    related.append(nxt)

                elif (
                    network_found
                    and
                    nxt["event_type"] == "PROCESS_CREATED"
                ):

                    process_found = True
                    related.append(nxt)
                    break

            if network_found and process_found:

                create_incident(
                    machine,
                    "Possible Lateral Movement",
                    "CRITICAL",
                    90,
                    related
                )

        # ---------------------------------------------------
        # Rule 6 : Persistence Detection
        # ---------------------------------------------------

        for i in range(len(machine_logs)):

            current = machine_logs[i]

            if current["event_type"] != "USER_CREATED":
                continue

            related = [current]

            password_changed = False
            login_success = False

            for j in range(i + 1, len(machine_logs)):

                nxt = machine_logs[j]

                if nxt["dt"] - current["dt"] > TIME_WINDOW:
                    break

                if (
                    not password_changed
                    and
                    nxt["event_type"] == "PASSWORD_CHANGED"
                ):

                    password_changed = True
                    related.append(nxt)

                elif (
                    password_changed
                    and
                    nxt["event_type"] == "LOGON_SUCCESS"
                ):

                    login_success = True
                    related.append(nxt)
                    break

            if password_changed and login_success:

                create_incident(
                    machine,
                    "Possible Persistence Established",
                    "HIGH",
                    85,
                    related
                )

        # ---------------------------------------------------
        # Rule 7 : Data Exfiltration Detection
        # ---------------------------------------------------

        file_access_logs = []

        for log in machine_logs:

            if log["event_type"] == "FILE_ACCESS":
                file_access_logs.append(log)

        if len(file_access_logs) >= 5:

            last_file = file_access_logs[-1]

            for log in machine_logs:

                if log["event_type"] != "NETWORK_CONNECTION":
                    continue

                if (
                    log["dt"] >= last_file["dt"]
                    and
                    log["dt"] - last_file["dt"] <= TIME_WINDOW
                ):

                    related = file_access_logs + [log]

                    create_incident(
                        machine,
                        "Possible Data Exfiltration",
                        "CRITICAL",
                        92,
                        related
                    )

                    break

        # ---------------------------------------------------
        # Rule 8 : Ransomware Detection
        # ---------------------------------------------------

        for i in range(len(machine_logs)):

            current = machine_logs[i]

            if current["event_type"] != "PROCESS_CREATED":
                continue

            related = [current]

            file_count = 0

            for j in range(i + 1, len(machine_logs)):

                nxt = machine_logs[j]

                if nxt["dt"] - current["dt"] > TIME_WINDOW:
                    break

                if nxt["event_type"] == "FILE_ACCESS":

                    related.append(nxt)
                    file_count += 1

            if file_count >= 10:

                create_incident(
                    machine,
                    "Possible Ransomware Activity",
                    "CRITICAL",
                    98,
                    related
                )

    # -------------------------------------------------------
    # Save incidents
    # -------------------------------------------------------

    with open(OUTPUT_FILE, "w") as f:
        json.dump(incidents, f, indent=4)
    for incident in incidents:
        generate_response_json(incident)

    save_incidents_to_db()
    print(f"{len(incidents)} incidents generated.")

if __name__ == "__main__":
    run_correlation()