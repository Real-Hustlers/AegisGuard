import sys
import json
import subprocess
from datetime import datetime

# --------------------------
# Platform & Helper Imports
# --------------------------
try:
    from database import get_connection
    from backend.analyzer.incident_enricher import IncidentEnricher
except ImportError:
    from database import get_connection
    from backend.analyzer.incident_enricher import IncidentEnricher

enricher = IncidentEnricher()


def log_message(conn, incident_id, message):
    """Write a terminal console log to the database."""
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO response_logs (incident_id, timestamp, message)
        VALUES (?, ?, ?)
    """, (incident_id, timestamp, message))
    conn.commit()


def get_settings(conn):
    """Retrieve settings as a dictionary."""
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    rows = cursor.fetchall()
    return {row[0]: row[1] for row in rows}


def execute_incident_playbook(conn, incident_id, enforce=None):
    """Execute or simulate remediation command for an incident."""

    cursor = conn.cursor()

    # -------------------------------------------------
    # Retrieve the requested incident from the database
    # -------------------------------------------------

    cursor.execute("""
        SELECT
            incident_id,
            threat_type,
            hostname,
            os,
            command_executed,
            status,
            action_taken
        FROM incidents
        WHERE incident_id = ?
    """, (incident_id,))

    row = cursor.fetchone()

    if not row:
        log_message(
            conn,
            incident_id,
            f"[ERROR] Incident {incident_id} not found."
        )
        return False

    (
        inc_id,
        threat_type,
        hostname,
        os_name,
        command,
        current_status,
        action_taken
    ) = row

    # -------------------------------------------------
    # Retrieve settings
    # -------------------------------------------------

    settings = get_settings(conn)

    simulation_mode = (
        str(settings.get("simulation_mode", "true")).lower()
        == "true"
    )

    # Allow explicit override
    if enforce is not None:
        simulation_mode = not enforce

    # -------------------------------------------------
    # Start execution
    # -------------------------------------------------

    log_message(
        conn,
        inc_id,
        f"[EXEC] Starting execution for incident {inc_id}..."
    )

    # -------------------------------------------------
    # Simulation Mode
    # -------------------------------------------------

    if simulation_mode:

        log_message(
            conn,
            inc_id,
            "[SIMULATION] Dry-run mode active. No host changes made."
        )

        log_message(
            conn,
            inc_id,
            f"[SIMULATION] Executing command: `{command}`"
        )

        log_message(
            conn,
            inc_id,
            f"[SIMULATION] SUCCESS: Playbook action "
            f"'{action_taken}' completed."
        )

        log_message(
            conn,
            inc_id,
            "[ALERT] Administrator notification simulated."
        )

        cursor.execute("""
            UPDATE incidents
            SET status = 'SIMULATED',
                alert_status = 'ALERT_SENT'
            WHERE incident_id = ?
        """, (inc_id,))

        conn.commit()

        return True

    # -------------------------------------------------
    # Real Enforcement Mode
    # -------------------------------------------------

    cursor.execute("""
        UPDATE incidents
        SET status = 'EXECUTING'
        WHERE incident_id = ?
    """, (inc_id,))

    conn.commit()

    log_message(
        conn,
        inc_id,
        f"[ACTIVE] Launching live remediation command "
        f"on system: `{command}`"
    )

    target_os = str(os_name or "Windows").lower()
    host_is_windows = sys.platform.startswith("win")

    # -------------------------------------------------
    # Platform mismatch protection
    # -------------------------------------------------

    if (
        ("linux" in target_os and host_is_windows)
        or
        ("windows" in target_os and not host_is_windows)
    ):

        log_message(
            conn,
            inc_id,
            f"[ACTIVE] WARNING: Target OS ({os_name}) "
            f"does not match current host platform "
            f"({sys.platform}). Falling back to simulation."
        )

        log_message(
            conn,
            inc_id,
            f"[ACTIVE] SUCCESS: Simulated execution "
            f"of `{command}` completed."
        )

        log_message(
            conn,
            inc_id,
            "[ALERT] Administrator notification simulated."
        )

        cursor.execute("""
            UPDATE incidents
            SET status = 'SIMULATED',
                alert_status = 'ALERT_SENT'
            WHERE incident_id = ?
        """, (inc_id,))

        conn.commit()

        return True

    # -------------------------------------------------
    # Execute command
    # -------------------------------------------------

    try:

        if host_is_windows:

            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    command
                ],
                capture_output=True,
                text=True,
                timeout=10
            )

        else:

            result = subprocess.run(
                [
                    "/bin/bash",
                    "-c",
                    command
                ],
                capture_output=True,
                text=True,
                timeout=10
            )

        # ---------------------------------------------
        # Successful execution
        # ---------------------------------------------

        if result.returncode == 0:

            log_message(
                conn,
                inc_id,
                "[ACTIVE] SUCCESS: Command returned exit code 0."
            )

            if result.stdout.strip():

                log_message(
                    conn,
                    inc_id,
                    f"[STDOUT] {result.stdout.strip()}"
                )

            cursor.execute("""
                UPDATE incidents
                SET status = 'EXECUTED',
                    alert_status = 'ALERT_SENT'
                WHERE incident_id = ?
            """, (inc_id,))

        # ---------------------------------------------
        # Failed execution
        # ---------------------------------------------

        else:

            log_message(
                conn,
                inc_id,
                f"[ACTIVE] ERROR: Command failed with "
                f"exit code {result.returncode}."
            )

            if result.stderr.strip():

                log_message(
                    conn,
                    inc_id,
                    f"[STDERR] {result.stderr.strip()}"
                )

            cursor.execute("""
                UPDATE incidents
                SET status = 'FAILED',
                    alert_status = 'ALERT_SENT'
                WHERE incident_id = ?
            """, (inc_id,))

    except subprocess.TimeoutExpired:

        log_message(
            conn,
            inc_id,
            "[ACTIVE] ERROR: Command execution timed out (10s limit)."
        )

        cursor.execute("""
            UPDATE incidents
            SET status = 'FAILED',
                alert_status = 'ALERT_SENT'
            WHERE incident_id = ?
        """, (inc_id,))

    except Exception as e:

        log_message(
            conn,
            inc_id,
            f"[ACTIVE] ERROR: Command failed to start. {str(e)}"
        )

        cursor.execute("""
            UPDATE incidents
            SET status = 'FAILED',
                alert_status = 'ALERT_SENT'
            WHERE incident_id = ?
        """, (inc_id,))

    conn.commit()

    return True


def get_highly_suspicious_entities(conn):
    """Aggregate threat scores by IP and hostname to identify top threats."""
    cursor = conn.cursor()

    # Get highly suspicious source IPs (count occurrences of HIGH/CRITICAL threat categories)
    cursor.execute("""
        SELECT source_ip, COUNT(*) as count, MAX(threat_level) as max_level
        FROM security_logs
        WHERE source_ip IS NOT NULL AND source_ip != '' AND UPPER(threat_level) IN ('HIGH', 'CRITICAL')
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 5
    """)
    ips = [{"ip": row[0], "count": row[1], "level": row[2]} for row in cursor.fetchall()]

    # Get highly suspicious systems (hosts)
    cursor.execute("""
        SELECT hostname, os, COUNT(*) as count, MAX(threat_level) as max_level
        FROM security_logs
        WHERE hostname IS NOT NULL AND hostname != '' AND UPPER(threat_level) IN ('HIGH', 'CRITICAL')
        GROUP BY hostname, os
        ORDER BY count DESC
        LIMIT 5
    """)
    hosts = [{"hostname": row[0], "os": row[1], "count": row[2], "level": row[3]} for row in cursor.fetchall()]

    return {"ips": ips, "hosts": hosts}



def scan_and_generate_incidents(conn):
    """Scan security logs and generate pending incident response records."""
    cursor = conn.cursor()

    # Query all security logs that don't have an incident generated yet
    cursor.execute("""
        SELECT log_id, machine_id, hostname, os, timestamp, event_type,
               user, source_ip, process, file_path, severity, raw_log,
               ml_prediction, ml_confidence, threat_level
        FROM security_logs
        WHERE log_id NOT IN (SELECT DISTINCT log_id FROM incidents WHERE log_id IS NOT NULL)
    """)
    logs = cursor.fetchall()

    if not logs:
        return 0

    incidents_created = 0
    settings = get_settings(conn)
    auto_respond = settings.get("auto_response_enabled", "true") == "true"

    for log in logs:
        (log_id, machine_id, hostname, os_name, timestamp, event_type,
         user, source_ip, process, file_path, severity, raw_log,
         ml_prediction, ml_confidence, threat_level) = log

        threat_type = None
        playbook_steps = []
        command_windows = ""
        command_linux = ""
        action_taken = ""

        # Normalize strings for matching
        event_type_upper = str(event_type or "").upper()
        ml_pred_upper = str(ml_prediction or "").upper()
        raw_log_lower = str(raw_log or "").lower()

        # -----------------------------
        # Threat 1: Brute Force Attack
        # -----------------------------
        if ml_pred_upper == "BRUTE_FORCE" or "brute-force" in raw_log_lower or "multiple failed login" in raw_log_lower:
            threat_type = "Brute Force Attack"
            ip = source_ip or "10.12.32.108"
            playbook_steps = ["Block the attacker's IP", "Send alerts to administrators", "Generate an incident report"]
            command_windows = f'netsh advfirewall firewall add rule name="Block Hacker" dir=in action=block remoteip={ip}'
            command_linux = f'iptables -A INPUT -s {ip} -j DROP'
            action_taken = f"Blocked malicious attacker IP: {ip}"
            if user:
                playbook_steps.insert(1, "Disable compromised account")
                command_windows += f'; net user {user} /active:no'
                command_linux += f'; passwd -l {user}'
                action_taken += f" and disabled account '{user}'"

        # -----------------------------
        # Threat 2: Privilege Escalation
        # -----------------------------
        elif ml_pred_upper == "PRIVILEGE_ESCALATION" or event_type_upper == "PRIVILEGE_ESCALATION":
            threat_type = "Privilege Escalation"
            proc = process or "suspicious_process"
            uname = user or "developer"
            playbook_steps = ["Kill suspicious process", "Stop suspicious services", "Disable sudo temporarily", "Lock the user account", "Generate an incident report", "Send alerts to administrators"]
            proc_no_ext = proc.replace(".exe", "") if proc.endswith(".exe") else proc
            command_windows = f'Stop-Process -Name "{proc_no_ext}" -Force; Stop-Service -Name SuspiciousService -Force'
            command_linux = f'pkill {proc}; systemctl stop suspicious.service; passwd -l {uname}'
            action_taken = f"Terminated process '{proc}', stopped suspicious services, and locked account '{uname}'"

        # -----------------------------
        # Threat 3: Malware
        # -----------------------------
        elif ml_pred_upper == "MALWARE" or (event_type_upper == "DEFENDER_ALERT" and "trojan" in raw_log_lower):
            threat_type = "Malware Infection"
            proc = process or "MsMpEng.exe"
            file_p = file_path or "C:\\Downloads\\malware.exe"
            playbook_steps = ["Stop malicious process", "Stop suspicious services", "Quarantine File", "Isolate infected machine", "Send alerts to administrators", "Generate an incident report"]
            proc_no_ext = proc.replace(".exe", "") if proc.endswith(".exe") else proc
            command_windows = f'Stop-Process -Name "{proc_no_ext}" -Force; Get-Service | Where-Object {{$_.Name -match "Suspicious|Malware"}} | Stop-Service -Force; Move-Item -Path "{file_p}" -Destination "C:\\Quarantine\\"; Disable-NetAdapter -Name * -Confirm:$false'
            command_linux = f'pkill {proc}; systemctl stop suspicious.service; mv {file_p} /tmp/quarantine/; ip link set eth0 down'
            action_taken = f"Isolated infected host, terminated process '{proc}', stopped suspicious services, and quarantined '{file_p}'"

        # -----------------------------
        # Threat 4: USB Attack
        # -----------------------------
        elif event_type_upper == "USB_CONNECTED" and (ml_pred_upper in ["USB_THREAT", "USB_ATTACK"] or severity == "HIGH" or "unknown usb" in raw_log_lower):
            threat_type = "USB Attack"
            playbook_steps = ["Disable USB automatically", "Send alerts to administrators", "Generate an incident report"]
            command_windows = r'Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR -Name Start -Value 4'
            command_linux = 'echo "disable usb" > /sys/bus/usb/drivers/usb/unbind'
            action_taken = "Disabled USB storage drivers/ports"

        # -----------------------------
        # Threat 5: Defender Alert
        # -----------------------------
        elif event_type_upper == "DEFENDER_ALERT":
            threat_type = "Defender Alert"
            playbook_steps = ["Start Windows Defender scan", "Send alerts to administrators", "Generate an incident report"]
            command_windows = 'Start-MpScan -ScanType FullScan'
            command_linux = 'clamscan -r /'
            action_taken = "Initiated full system anti-virus scan"

        # If matched, create incident
        if threat_type:
            incident_id = f"INC-{log_id}"
            steps_json = json.dumps(playbook_steps)
            incident_data = {
                "incident_id": incident_id,
                "threat_type": threat_type,
                "hostname": hostname,
                "os": os_name,
                "source_ip": source_ip,
                "user": user,
                "process": process,
                "file_path": file_path,
                "severity": severity,
                "timestamp": timestamp,
                "playbook_steps": playbook_steps,
                "action_taken": action_taken,
                "ml_prediction": ml_prediction,
                "ml_confidence": ml_confidence,
            }

            incident_data = enricher.enrich(incident_data)

            # Get playbook information
            playbook_steps = incident_data["playbook"]["responses"]
            severity = incident_data["playbook"]["severity"]

            steps_json = json.dumps(playbook_steps)
            incident_report = json.dumps(incident_data)

            # Choose command based on target OS or default to windows
            target_os = str(os_name or "Windows").lower()
            if "linux" in target_os or "ubuntu" in target_os:
                command = command_linux
            else:
                command = command_windows

            cursor.execute("""
                INSERT OR REPLACE INTO incidents (
                    incident_id, log_id, threat_type, hostname, os, source_ip,
                    user, process, file_path, severity, timestamp, status,
                    action_taken, command_executed, playbook_steps,
                    incident_report, alert_status, mitre
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_id, log_id, threat_type, hostname, os_name, source_ip,
                user, process, file_path, severity, timestamp, "PENDING",
                action_taken, command, steps_json,
                incident_report, "PENDING_ALERT", json.dumps(incident_data["mitre"])
            ))
            conn.commit()
            incidents_created += 1

            log_message(conn, incident_id, f"[INIT] Threat detected: {threat_type} on host '{hostname}' ({os_name})")
            log_message(conn, incident_id, f"[INIT] Playbook steps: {', '.join(playbook_steps)}")
            log_message(conn, incident_id, f"[INIT] Remediation command ready: `{command}`")
            log_message(conn, incident_id, f"[INIT] Incident report generated.")
            log_message(conn, incident_id, f"[ALERT] Alert scheduled for administrators.")

            # Execute automatically if enabled
            if auto_respond:
                execute_incident_playbook(conn, incident_id)

    return incidents_created