import sys
import json
from pathlib import Path
from flask import Flask, jsonify, render_template, request
import os


def debug_print(message):
    print(message, flush=True)

# ============================================================
# PATH HELPERS
# ============================================================

def resource_path(relative_path):
    """
    Get path to bundled read-only resources.
    """

    if getattr(sys, "frozen", False):
        base_path = Path(sys._MEIPASS)
        debug_print(f"[FROZEN] _MEIPASS = {base_path}")
    else:
        base_path = Path(__file__).resolve().parents[2]
        debug_print(f"[SOURCE] BASE = {base_path}")

    path = base_path / relative_path

    debug_print(f"[RESOURCE] {relative_path}")
    debug_print(f"[RESOURCE PATH] {path}")
    debug_print(f"[RESOURCE EXISTS] {path.exists()}")

    return path


def app_data_path(relative_path):
    """
    Files that the application creates or modifies.
    """

    if getattr(sys, "frozen", False):
        base_path = Path(sys.executable).resolve().parent
    else:
        base_path = Path(__file__).resolve().parents[2]

    path = base_path / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)

    return path


# ============================================================
# BASE DIRECTORY
# ============================================================

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parents[2]


# ============================================================
# PYTHON PATH
# ============================================================

if not getattr(sys, "frozen", False):
    sys.path.insert(0, str(BASE_DIR))


# ============================================================
# FLASK RESOURCE PATHS
# ============================================================

TEMPLATE_PATH = resource_path("templates")
STATIC_PATH = resource_path("static")


# ============================================================
# DEBUG INFORMATION
# ============================================================

debug_print("=" * 70)
debug_print("AEGISGUARD RESOURCE DEBUG")
debug_print(f"Frozen              : {getattr(sys, 'frozen', False)}")
debug_print(f"Executable          : {sys.executable}")
debug_print(f"__file__            : {__file__}")

if getattr(sys, "frozen", False):
    debug_print(f"_MEIPASS            : {sys._MEIPASS}")

debug_print(f"BASE_DIR            : {BASE_DIR}")
debug_print(f"TEMPLATE_PATH       : {TEMPLATE_PATH}")
debug_print(f"TEMPLATE_EXISTS     : {TEMPLATE_PATH.exists()}")
debug_print(f"INDEX_PATH          : {TEMPLATE_PATH / 'index.html'}")
debug_print(f"INDEX_EXISTS        : {(TEMPLATE_PATH / 'index.html').exists()}")
debug_print(f"STATIC_PATH         : {STATIC_PATH}")
debug_print(f"STATIC_EXISTS       : {STATIC_PATH.exists()}")

if TEMPLATE_PATH.exists():
    debug_print("TEMPLATE CONTENTS:")
    for item in TEMPLATE_PATH.iterdir():
        debug_print(f"  -> {item}")

debug_print("=" * 70)


# ============================================================
# FLASK
# ============================================================

app = Flask(
    __name__,
    template_folder=str(TEMPLATE_PATH),
    static_folder=str(STATIC_PATH),
)

try:
    from service import get_alerts, get_dashboard_summary, get_events, get_devices
    from mysql.merge_log_sql import import_classified_logs_to_db
    from database import get_connection
    import incident_response
except ImportError:
    from backend.analyzer.service import get_alerts, get_dashboard_summary, get_events, get_devices
    from mysql.merge_log_sql import import_classified_logs_to_db
    from backend.analyzer.database import get_connection
    from backend.analyzer import incident_response

try:
    from ingestion.classifier import classify_logs
except ImportError:
    try:
        from backend.analyzer.ingestion.classifier import classify_logs
    except Exception:
        classify_logs = None


UPLOAD_FOLDER = app_data_path("test")
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

@app.route("/api/upload_logs", methods=["POST"])
def upload_logs():

    data = request.json or {}

    machine_id = data.get("machine_id", "UNKNOWN")
    logs = data.get("logs", [])

    # -----------------------------------------
    # Save uploaded payload
    # -----------------------------------------

    file_path = UPLOAD_FOLDER / f"{machine_id}.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, default=str)

    # -----------------------------------------
    # Windows logs file
    # -----------------------------------------

    WINDOWS_LOG_FILE = app_data_path(
        "data/windows_logs.json"
    )

    # Make sure parent directory exists
    WINDOWS_LOG_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    existing_logs = []

    # -----------------------------------------
    # Load existing logs
    # -----------------------------------------

    if WINDOWS_LOG_FILE.exists():

        try:

            with open(
                WINDOWS_LOG_FILE,
                "r",
                encoding="utf-8"
            ) as f:

                existing_logs = json.load(f)

            if not isinstance(existing_logs, list):
                existing_logs = []

        except json.JSONDecodeError as e:

            print("WARNING: windows_logs.json is corrupted.")
            print("JSON error:", e)

            backup_file = WINDOWS_LOG_FILE.with_name(
                "windows_logs_corrupted_backup.json"
            )

            try:

                WINDOWS_LOG_FILE.replace(
                    backup_file
                )

                print(
                    "Corrupted file backed up to:",
                    backup_file
                )

            except Exception as backup_error:

                print(
                    "Backup failed:",
                    backup_error
                )

            existing_logs = []

    # -----------------------------------------
    # Build existing RecordId set
    # -----------------------------------------

    existing_record_ids = {
        log.get("RecordId")
        for log in existing_logs
        if log.get("RecordId") is not None
    }

    # -----------------------------------------
    # Append only new logs
    # -----------------------------------------

    new_logs = 0

    for log in logs:

        record_id = log.get("RecordId")

        if record_id not in existing_record_ids:

            existing_logs.append(log)

            if record_id is not None:
                existing_record_ids.add(record_id)

            new_logs += 1

    # -----------------------------------------
    # Save Windows logs
    # -----------------------------------------

    with open(
        WINDOWS_LOG_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            existing_logs,
            f,
            indent=4,
            default=str
        )

    print(
        f"Received {len(logs)} logs, "
        f"added {new_logs} new logs."
    )

    # -----------------------------------------
    # Run backend pipeline
    # -----------------------------------------

    try:

        from ingestion.import_merge import merge_logs
        from ingestion.classifier import classify_logs
        from ingestion.correlation_engine import run_correlation

        MERGED_LOGS = app_data_path(
            "output/merged_logs.json"
        )

        CLASSIFIED_LOGS = app_data_path(
            "output/classified_logs.json"
        )

        merge_logs()

        classify_logs(
            str(MERGED_LOGS),
            str(CLASSIFIED_LOGS)
        )

        print("Importing classified logs into database...", flush=True)

        import_classified_logs_to_db(
            str(CLASSIFIED_LOGS)
        )

        print("Classified logs imported into database.", flush=True)

        run_correlation()

    except Exception as e:

        print("Pipeline error:", e)

        return jsonify({
            "status": "error",
            "message": "Logs received but backend pipeline failed",
            "error": str(e),
            "machine": machine_id,
            "logs_received": len(logs),
            "new_logs_added": new_logs
        }), 500

    # -----------------------------------------
    # SUCCESS RESPONSE
    # -----------------------------------------

    return jsonify({
        "status": "success",
        "machine": machine_id,
        "logs_received": len(logs),
        "new_logs_added": new_logs
    }), 200



def run_ml_classification():
    """Classify merged logs with the trained ML model."""

    if classify_logs is None:
        return

    input_path = app_data_path("output/merged_logs.json")
    output_path = app_data_path("output/classified_logs.json")

    if input_path.exists():
        classify_logs(
            str(input_path),
            str(output_path)
        )

        import_classified_logs_to_db(str(output_path))


@app.route("/")
def home():
    """Render the offline dashboard page."""
    return render_template("index.html")


@app.route("/api/dashboard")
def dashboard():
    """Return dashboard metrics and chart payloads from the service layer."""
    return jsonify(get_dashboard_summary())


@app.route("/api/alerts")
def alerts():
    """Return alert records for the dashboard."""
    return jsonify(get_alerts())


@app.route("/api/events")
def events():
    """Return normalized event log records for the table."""
    hostname = request.args.get('hostname')
    return jsonify(get_events(hostname))


@app.route("/api/devices")
def devices():
    """Return monitored device summaries for the devices dashboard."""
    return jsonify(get_devices())


@app.route("/api/incidents")
def get_incidents():
    """Fetch all incidents."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT incident_id, log_id, threat_type, hostname, os, source_ip,
               user, process, file_path, severity, timestamp, status,
               action_taken, command_executed, playbook_steps, incident_report, alert_status, mitre
        FROM incidents
        ORDER BY timestamp DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    
    incidents = []
    for r in rows:
        incident_report = None
        try:
            incident_report = json.loads(r["incident_report"]) if r["incident_report"] else None
        except Exception:
            incident_report = r["incident_report"]

        incidents.append({
            "incident_id": r["incident_id"],
            "log_id": r["log_id"],
            "threat_type": r["threat_type"],
            "hostname": r["hostname"],
            "os": r["os"],
            "source_ip": r["source_ip"],
            "user": r["user"],
            "process": r["process"],
            "file_path": r["file_path"],
            "severity": r["severity"],
            "timestamp": r["timestamp"],
            "status": r["status"],
            "action_taken": r["action_taken"],
            "command_executed": r["command_executed"],
            "playbook_steps": json.loads(r["playbook_steps"]) if r["playbook_steps"] else [],
            "incident_report": incident_report,
            "ml_prediction": incident_report.get("ml_prediction") if isinstance(incident_report, dict) else None,
            "ml_confidence": incident_report.get("ml_confidence") if isinstance(incident_report, dict) else None,
            "alert_status": r["alert_status"],
            "mitre": json.loads(r["mitre"]) if r["mitre"] else {
                "technique_id": "Unknown",
                "technique": "Unknown",
                "tactic": "Unknown"
            }
        })
    return jsonify(incidents)


@app.route("/api/incidents/logs")
def get_incident_logs():
    """Get terminal response logs."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT log_id, incident_id, timestamp, message
        FROM response_logs
        ORDER BY log_id ASC
    """)
    rows = cursor.fetchall()
    conn.close()
    
    logs = []
    for r in rows:
        logs.append({
            "log_id": r["log_id"],
            "incident_id": r["incident_id"],
            "timestamp": r["timestamp"],
            "message": r["message"]
        })
    return jsonify(logs)


@app.route('/api/incidents/suspicious')
def get_suspicious_entities():
    """Get top suspicious IPs and infected hosts."""
    conn = get_connection()
    try:
        res = incident_response.get_highly_suspicious_entities(conn)
    finally:
        conn.close()
    return jsonify(res)


@app.route('/api/incidents/settings', methods=["GET", "POST"])
def get_or_post_settings():
    """Get or update automated response settings."""
    conn = get_connection()
    cursor = conn.cursor()
    if request.method == "POST":
        data = request.json or {}
        for key in ["auto_response_enabled", "simulation_mode"]:
            if key in data:
                val = "true" if data[key] else "false"
                cursor.execute("""
                    INSERT OR REPLACE INTO settings (key, value)
                    VALUES (?, ?)
                """, (key, val))
        conn.commit()

    cursor.execute("SELECT key, value FROM settings")
    settings = {r["key"]: (r["value"] == "true") for r in cursor.fetchall()}
    conn.close()
    return jsonify(settings)


@app.route('/api/incidents/execute', methods=["POST"])
def execute_incident():
    data = request.json or {}
    incident_id = data.get("incident_id")
    enforce = data.get("enforce", False)

    if not incident_id:
        return jsonify({"error": "Missing incident_id"}), 400

    conn = get_connection()
    try:
        success = incident_response.execute_incident_playbook(conn, incident_id, enforce=enforce)
    finally:
        conn.close()

    if success:
        return jsonify({"success": True})
    return jsonify({"error": "Incident not found"}), 404


@app.route('/api/incidents/reset', methods=["POST"])
def reset_incidents():
    """Wipe incidents and logs to restore a clean state."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM incidents")
    cursor.execute("DELETE FROM response_logs")
    conn.commit()

    # Re-run log scan to populate
    incident_response.scan_and_generate_incidents(conn)
    conn.close()
    return jsonify({"success": True})


@app.route('/api/alerts/summary')
def alert_summary():
    """Return a simple correlation summary for a given log_id."""
    log_id = request.args.get('log_id')
    if not log_id:
        return jsonify({'error': 'missing log_id'}), 400

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_logs WHERE log_id = ?", (log_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'log not found'}), 404

    # Convert row to dict for safe access
    row_dict = dict(row)

    # Try to resolve MITRE mapping for the ML prediction
    try:
        from ingestion.mitre_mapper import get_mitre_mapping
    except Exception:
        try:
            from backend.analyzer.ingestion.mitre_mapper import get_mitre_mapping
        except Exception:
            def get_mitre_mapping(x):
                return {"technique_id": "Unknown", "technique": "Unknown", "tactic": "Unknown"}

    mitre = get_mitre_mapping(row_dict.get('ml_prediction'))

    # Build basic summary (include additional fields available in security_logs)
    event = {
        'id': row_dict.get('log_id'),
        'timestamp': row_dict.get('timestamp'),
        'hostname': row_dict.get('hostname'),
        'ip': row_dict.get('source_ip'),
        'os': row_dict.get('os'),
        'user': row_dict.get('user'),
        'process': row_dict.get('process'),
        'file_path': row_dict.get('file_path'),
        'destination_ip': row_dict.get('destination_ip'),
        'severity': row_dict.get('severity'),
        'ml_prediction': row_dict.get('ml_prediction'),
        'ml_confidence': row_dict.get('ml_confidence'),
        'raw_log': row_dict.get('raw_log'),
        'threat_category': row_dict.get('threat_category'),
        'threat_score': row_dict.get('threat_score')
    }

    # Find nearby related logs (same host within +/- 5 minutes)
    try:
        from datetime import datetime, timedelta
        ts = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
        start = (ts - timedelta(minutes=5)).isoformat()
        end = (ts + timedelta(minutes=5)).isoformat()
    except Exception:
        start = None; end = None

    related = []
    if start and end:
        cursor.execute("""
            SELECT log_id, timestamp, raw_log, severity
            FROM security_logs
            WHERE hostname = ? AND timestamp BETWEEN ? AND ?
            ORDER BY timestamp ASC
            LIMIT 50
        """, (row_dict.get('hostname'), start, end))
        for r in cursor.fetchall():
            rr = dict(r)
            related.append({
                'id': rr.get('log_id'),
                'timestamp': rr.get('timestamp'),
                'raw_log': rr.get('raw_log'),
                'severity': rr.get('severity')
            })

    # Simple heuristic correlation findings
    findings = []
    raw = (row_dict.get('raw_log') or '').lower()
    if 'failed' in raw and 'login' in raw:
        findings.append('Multiple failed login attempts detected')
    if 'sudo' in raw or 'privilege' in raw or 'elevat' in raw:
        findings.append('Possible privilege escalation activity')
    if 'powershell' in raw or 'cmd.exe' in raw or 'rundll32' in raw:
        findings.append('Suspicious process execution (script interpreter)')
    if not findings:
        findings.append('No immediate correlation findings; inspect related logs')

    conn.close()

    return jsonify({
        'event': event,
        'related': related,
        'findings': findings,
        'mitre': mitre
    })

run_ml_classification()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )

# @app.route("/api/incidents/suspicious")
# def get_suspicious_entities():
    # """Get top suspicious IPs and infected hosts."""
    # conn = get_connection()
    # try:
    #     res = incident_response.get_highly_suspicious_entities(conn)
    # finally:
    #     conn.close()
    # return jsonify(res)


# @app.route("/api/incidents/settings", methods=["GET", "POST"])
# def get_or_post_settings():
#     """Get or update automated response settings."""
#     conn = get_connection()
#     cursor = conn.cursor()
#     if request.method == "POST":
#         data = request.json or {}
#         for key in ["auto_response_enabled", "simulation_mode"]:
#             if key in data:
#                 val = "true" if data[key] else "false"
#                 cursor.execute("""
#                     INSERT OR REPLACE INTO settings (key, value)
#                     VALUES (?, ?)
#                 """, (key, val))
#         conn.commit()
    
#     cursor.execute("SELECT key, value FROM settings")
#     settings = {r["key"]: (r["value"] == "true") for r in cursor.fetchall()}
#     conn.close()
#     return jsonify(settings)


# # @app.route("/api/incidents/execute", methods=["POST"])
# # def execute_incident():
#     """Manually run or simulate an incident playbook."""
#     data = request.json or {}
#     incident_id = data.get("incident_id")
#     enforce = data.get("enforce", False)
    
#     if not incident_id:
#         return jsonify({"error": "Missing incident_id"}), 400
        
#     conn = get_connection()
#     try:
#         success = incident_response.execute_incident_playbook(conn, incident_id, enforce=enforce)
#     finally:
#         conn.close()
        
#     if success:
#         return jsonify({"success": True})
#     return jsonify({"error": "Incident not found"}), 404


# # @app.route("/api/incidents/reset", methods=["POST"])
# # def reset_incidents():
#     """Wipe incidents and logs to restore a clean state."""
#     conn = get_connection()
#     cursor = conn.cursor()
#     cursor.execute("DELETE FROM incidents")
#     cursor.execute("DELETE FROM response_logs")
#     conn.commit()
    
#     # Re-run log scan to populate
#     incident_response.scan_and_generate_incidents(conn)
#     conn.close()
#     return jsonify({"success": True})