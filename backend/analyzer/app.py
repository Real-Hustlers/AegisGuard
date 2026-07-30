import sys
import json
from pathlib import Path
from flask import Flask, jsonify, render_template, request
import os

BASE_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE_DIR))

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
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


UPLOAD_FOLDER = Path(__file__).parent / "test"
UPLOAD_FOLDER.mkdir(exist_ok=True)

@app.route("/api/upload_logs", methods=["POST"])
def upload_logs():

    data = request.json

    machine_id = data.get("machine_id", "UNKNOWN")
    logs = data.get("logs", [])

    # -----------------------------------------
    # Save uploaded payload (optional)
    # -----------------------------------------

    file_path = UPLOAD_FOLDER / f"{machine_id}.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

    # -----------------------------------------
    # Append uploaded logs to windows_logs.json
    # -----------------------------------------

    WINDOWS_LOG_FILE = (
        BASE_DIR
        / "backend"
        / "analyzer"
        / "output"
        / "windows_logs.json"
    )

    if WINDOWS_LOG_FILE.exists():
        with open(WINDOWS_LOG_FILE, "r", encoding="utf-8") as f:
            existing_logs = json.load(f)
    else:
        existing_logs = []

    # Build a set of existing RecordIds
    existing_record_ids = {
        log.get("record_id")
        for log in existing_logs
        if log.get("record_id") is not None
    }

    # Append only new logs
    new_logs = 0

    for log in logs:

        record_id = log.get("record_id")

        if record_id not in existing_record_ids:

            existing_logs.append(log)
            existing_record_ids.add(record_id)
            new_logs += 1

    with open(WINDOWS_LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(existing_logs, f, indent=4)

    # -----------------------------------------
    # Run backend pipeline
    # -----------------------------------------

    from ingestion.import_merge import merge_logs
    from ingestion.classifier import classify_logs
    from ingestion.correlation_engine import run_correlation

    merge_logs()

    classify_logs(
        "output/merged_logs.json",
        "output/classified_logs.json"
    )

    run_correlation()

    return jsonify({
        "status": "success",
        "machine": machine_id,
        "logs_received": len(logs),
        "new_logs_added": new_logs
    })


def run_ml_classification():
    """Classify merged logs with the trained ML model when the backend starts."""
    if classify_logs is None:
        return

    candidate_inputs = [
        BASE_DIR / "backend" / "analyzer" / "ingestion" / "output" / "merged_logs.json",
        BASE_DIR / "backend" / "analyzer" / "output" / "merged_logs.json",
    ]
    candidate_outputs = [
        BASE_DIR / "backend" / "analyzer" / "ingestion" / "output" / "classified_logs.json",
        BASE_DIR / "backend" / "analyzer" / "output" / "classified_logs.json",
    ]

    for input_path, output_path in zip(candidate_inputs, candidate_outputs):
        if input_path.exists():
            classify_logs(str(input_path), str(output_path))
            import_classified_logs_to_db(str(output_path))
            return


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
    app.run(host="127.0.0.1", port=5000, debug=True)

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


