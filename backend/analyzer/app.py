import sys
import json
import os
import threading
from pathlib import Path
from datetime import datetime, timedelta

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
)


# ============================================================
# PIPELINE CONCURRENCY
# ============================================================

# Only one Collector upload is allowed to modify the shared
# analysis pipeline files at a time.
#
# This prevents:
#
# Upload 1 -> merged_logs.json
# Upload 2 -> merged_logs.json at same time
#
# which previously caused JSONDecodeError / partial files.
pipeline_lock = threading.Lock()


# ============================================================
# DEBUG
# ============================================================

def debug_print(message):
    print(message, flush=True)


# ============================================================
# ATOMIC JSON WRITER
# ============================================================

def atomic_json_write(path, data):
    """
    Safely write JSON.

    The content is first written completely to a temporary file,
    then the temporary file atomically replaces the destination.

    This prevents another thread from reading an empty or
    partially-written JSON file.
    """

    path = Path(path)

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temp_path = path.with_suffix(
        path.suffix + ".tmp"
    )

    try:

        with open(
            temp_path,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                indent=4,
                default=str
            )

            f.flush()

            os.fsync(
                f.fileno()
            )

        os.replace(
            temp_path,
            path
        )

    except Exception:

        try:

            if temp_path.exists():
                temp_path.unlink()

        except Exception:
            pass

        raise


# ============================================================
# PATH HELPERS
# ============================================================

def resource_path(relative_path):
    """
    Get path to bundled read-only resources.

    Source:
        project root

    PyInstaller:
        sys._MEIPASS
    """

    if getattr(sys, "frozen", False):

        base_path = Path(
            sys._MEIPASS
        )

        debug_print(
            f"[FROZEN] _MEIPASS = {base_path}"
        )

    else:

        base_path = (
            Path(__file__)
            .resolve()
            .parents[2]
        )

        debug_print(
            f"[SOURCE] BASE = {base_path}"
        )

    path = (
        base_path
        /
        relative_path
    )

    debug_print(
        f"[RESOURCE] {relative_path}"
    )

    debug_print(
        f"[RESOURCE PATH] {path}"
    )

    debug_print(
        f"[RESOURCE EXISTS] {path.exists()}"
    )

    return path


def app_data_path(relative_path):
    """
    Return a writable application path.

    Source:
        project root

    PyInstaller:
        directory containing app.exe
    """

    if getattr(sys, "frozen", False):

        base_path = (
            Path(sys.executable)
            .resolve()
            .parent
        )

    else:

        base_path = (
            Path(__file__)
            .resolve()
            .parents[2]
        )

    path = (
        base_path
        /
        relative_path
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    return path


# ============================================================
# BASE DIRECTORY
# ============================================================

if getattr(sys, "frozen", False):

    BASE_DIR = (
        Path(sys.executable)
        .resolve()
        .parent
    )

else:

    BASE_DIR = (
        Path(__file__)
        .resolve()
        .parents[2]
    )


# ============================================================
# PYTHON PATH
# ============================================================

if not getattr(sys, "frozen", False):

    base_string = str(
        BASE_DIR
    )

    if base_string not in sys.path:

        sys.path.insert(
            0,
            base_string
        )


# ============================================================
# FLASK RESOURCE PATHS
# ============================================================

TEMPLATE_PATH = resource_path(
    "templates"
)

STATIC_PATH = resource_path(
    "static"
)


# ============================================================
# DEBUG INFORMATION
# ============================================================

debug_print(
    "=" * 70
)

debug_print(
    "AEGISGUARD RESOURCE DEBUG"
)

debug_print(
    f"Frozen              : "
    f"{getattr(sys, 'frozen', False)}"
)

debug_print(
    f"Executable          : "
    f"{sys.executable}"
)

debug_print(
    f"__file__            : "
    f"{__file__}"
)

if getattr(sys, "frozen", False):

    debug_print(
        f"_MEIPASS            : "
        f"{sys._MEIPASS}"
    )

debug_print(
    f"BASE_DIR            : "
    f"{BASE_DIR}"
)

debug_print(
    f"TEMPLATE_PATH       : "
    f"{TEMPLATE_PATH}"
)

debug_print(
    f"TEMPLATE_EXISTS     : "
    f"{TEMPLATE_PATH.exists()}"
)

debug_print(
    f"INDEX_PATH          : "
    f"{TEMPLATE_PATH / 'index.html'}"
)

debug_print(
    f"INDEX_EXISTS        : "
    f"{(TEMPLATE_PATH / 'index.html').exists()}"
)

debug_print(
    f"STATIC_PATH         : "
    f"{STATIC_PATH}"
)

debug_print(
    f"STATIC_EXISTS       : "
    f"{STATIC_PATH.exists()}"
)

if TEMPLATE_PATH.exists():

    debug_print(
        "TEMPLATE CONTENTS:"
    )

    for item in TEMPLATE_PATH.iterdir():

        debug_print(
            f"  -> {item}"
        )

debug_print(
    "=" * 70
)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(
    __name__,
    template_folder=str(
        TEMPLATE_PATH
    ),
    static_folder=str(
        STATIC_PATH
    ),
)


# ============================================================
# APPLICATION IMPORTS
# ============================================================

try:

    from service import (
        get_alerts,
        get_dashboard_summary,
        get_events,
        get_devices,
    )

except ImportError:

    from backend.analyzer.service import (
        get_alerts,
        get_dashboard_summary,
        get_events,
        get_devices,
    )


try:

    from mysql.merge_log_sql import (
        import_classified_logs_to_db
    )

except ImportError:

    from backend.analyzer.mysql.merge_log_sql import (
        import_classified_logs_to_db
    )


try:

    from database import (
        get_connection
    )

except ImportError:

    from backend.analyzer.database import (
        get_connection
    )


try:

    import incident_response

except ImportError:

    from backend.analyzer import (
        incident_response
    )


try:

    from ingestion.classifier import (
        classify_logs
    )

except ImportError:

    try:

        from backend.analyzer.ingestion.classifier import (
            classify_logs
        )

    except Exception as e:

        debug_print(
            f"Classifier import failed: {e}"
        )

        classify_logs = None


# ============================================================
# UPLOAD CONFIGURATION
# ============================================================

UPLOAD_FOLDER = app_data_path(
    "test"
)

UPLOAD_FOLDER.mkdir(
    parents=True,
    exist_ok=True
)


WINDOWS_LOG_FILE = app_data_path(
    "data/windows_logs.json"
)


# ============================================================
# UPLOAD LOGS API
# ============================================================

@app.route(
    "/api/upload_logs",
    methods=["POST"]
)
def upload_logs():
    """
    Receive logs from AegisGuard Collector.

    Pipeline:

        Collector
            ↓
        windows_logs.json
            ↓
        merge_logs()
            ↓
        classifier
            ↓
        SQLite
            ↓
        correlation engine

    Only one upload may execute this pipeline at a time.
    """

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    machine_id = data.get(
        "machine_id",
        "UNKNOWN"
    )

    logs = data.get(
        "logs",
        []
    )

    if not isinstance(
        logs,
        list
    ):

        return jsonify({
            "status": "error",
            "message": (
                "'logs' must be a list"
            ),
            "machine": machine_id
        }), 400

    # ========================================================
    # SERIALIZE SHARED PIPELINE
    # ========================================================

    with pipeline_lock:

        debug_print(
            f"[PIPELINE] Lock acquired for "
            f"machine {machine_id}"
        )

        try:

            # =================================================
            # SAVE LATEST MACHINE PAYLOAD
            # =================================================

            file_path = (
                UPLOAD_FOLDER
                /
                f"{machine_id}.json"
            )

            atomic_json_write(
                file_path,
                data
            )

            # =================================================
            # LOAD EXISTING WINDOWS LOGS
            # =================================================

            WINDOWS_LOG_FILE.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            existing_logs = []

            if WINDOWS_LOG_FILE.exists():

                try:

                    with open(
                        WINDOWS_LOG_FILE,
                        "r",
                        encoding="utf-8"
                    ) as f:

                        existing_logs = (
                            json.load(f)
                        )

                    if not isinstance(
                        existing_logs,
                        list
                    ):

                        existing_logs = []

                except json.JSONDecodeError as e:

                    debug_print(
                        "WARNING: "
                        "windows_logs.json "
                        "is corrupted."
                    )

                    debug_print(
                        f"JSON error: {e}"
                    )

                    backup_file = (
                        WINDOWS_LOG_FILE
                        .with_name(
                            "windows_logs_"
                            "corrupted_backup.json"
                        )
                    )

                    try:

                        WINDOWS_LOG_FILE.replace(
                            backup_file
                        )

                        debug_print(
                            "Corrupted file "
                            "backed up to: "
                            f"{backup_file}"
                        )

                    except Exception as backup_error:

                        debug_print(
                            "Backup failed: "
                            f"{backup_error}"
                        )

                    existing_logs = []

            # =================================================
            # BUILD RECORD-ID DEDUPLICATION SET
            # =================================================

            existing_record_ids = {

                (
                    log.get(
                        "record_id"
                    )
                    or
                    log.get(
                        "RecordId"
                    )
                )

                for log in existing_logs

                if (
                    log.get(
                        "record_id"
                    )
                    is not None

                    or

                    log.get(
                        "RecordId"
                    )
                    is not None
                )
            }

            # =================================================
            # APPEND NEW EVENTS
            # =================================================

            new_logs = 0

            for log in logs:

                if not isinstance(
                    log,
                    dict
                ):

                    continue

                record_id = (
                    log.get(
                        "record_id"
                    )
                    or
                    log.get(
                        "RecordId"
                    )
                )

                # If RecordId exists, deduplicate by it.
                if record_id is not None:

                    if (
                        record_id
                        in
                        existing_record_ids
                    ):

                        continue

                    existing_record_ids.add(
                        record_id
                    )

                # If RecordId does not exist, keep the log.
                existing_logs.append(
                    log
                )

                new_logs += 1

            # =================================================
            # ATOMIC WINDOWS LOG SAVE
            # =================================================

            atomic_json_write(
                WINDOWS_LOG_FILE,
                existing_logs
            )

            debug_print(
                f"Received {len(logs)} logs, "
                f"added {new_logs} new logs."
            )

            # =================================================
            # IMPORT ACTIVE PIPELINE
            # =================================================

            try:

                from ingestion.import_merge import (
                    merge_logs
                )

                from ingestion.classifier import (
                    classify_logs as active_classify_logs
                )

                from ingestion.correlation_engine import (
                    run_correlation
                )

            except ImportError:

                from backend.analyzer.ingestion.import_merge import (
                    merge_logs
                )

                from backend.analyzer.ingestion.classifier import (
                    classify_logs as active_classify_logs
                )

                from backend.analyzer.ingestion.correlation_engine import (
                    run_correlation
                )

            MERGED_LOGS = app_data_path(
                "output/merged_logs.json"
            )

            CLASSIFIED_LOGS = app_data_path(
                "output/classified_logs.json"
            )

            # =================================================
            # MERGE
            # =================================================

            debug_print(
                "[PIPELINE] Starting merge..."
            )

            merge_logs()

            # =================================================
            # CLASSIFICATION
            # =================================================

            debug_print(
                "[PIPELINE] Starting classification..."
            )

            active_classify_logs(
                str(MERGED_LOGS),
                str(CLASSIFIED_LOGS)
            )

            # =================================================
            # SQLITE IMPORT
            # =================================================

            debug_print(
                "Importing classified logs "
                "into database..."
            )

            import_classified_logs_to_db(
                str(CLASSIFIED_LOGS)
            )

            debug_print(
                "Classified logs imported "
                "into database."
            )

            # =================================================
            # CORRELATION
            # =================================================

            debug_print(
                "[PIPELINE] Starting correlation..."
            )

            run_correlation()

            debug_print(
                "[PIPELINE] Completed successfully."
            )

        except Exception as e:

            debug_print(
                f"Pipeline error: {e}"
            )

            return jsonify({
                "status": "error",
                "message": (
                    "Logs received but "
                    "backend pipeline failed"
                ),
                "error": str(e),
                "machine": machine_id,
                "logs_received": len(logs),
                "new_logs_added": (
                    locals().get(
                        "new_logs",
                        0
                    )
                )
            }), 500

        finally:

            debug_print(
                f"[PIPELINE] Lock released for "
                f"machine {machine_id}"
            )

    # ========================================================
    # SUCCESS RESPONSE
    # ========================================================

    return jsonify({
        "status": "success",
        "machine": machine_id,
        "logs_received": len(logs),
        "new_logs_added": new_logs
    }), 200


# ============================================================
# MANUAL / STARTUP ML CLASSIFICATION
# ============================================================

def run_ml_classification():
    """
    Classify existing merged logs when Analyzer starts.
    """

    if classify_logs is None:

        debug_print(
            "Classifier unavailable. "
            "Skipping startup classification."
        )

        return

    input_path = app_data_path(
        "output/merged_logs.json"
    )

    output_path = app_data_path(
        "output/classified_logs.json"
    )

    if not input_path.exists():

        debug_print(
            "No merged_logs.json found. "
            "Skipping startup classification."
        )

        return

    try:

        classify_logs(
            str(input_path),
            str(output_path)
        )

        import_classified_logs_to_db(
            str(output_path)
        )

    except json.JSONDecodeError as e:

        debug_print(
            "Startup classification skipped "
            "because merged_logs.json "
            f"is invalid: {e}"
        )

    except Exception as e:

        debug_print(
            "Startup classification error: "
            f"{e}"
        )


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    """Render the offline dashboard page."""

    return render_template(
        "index.html"
    )


# ============================================================
# DASHBOARD API
# ============================================================

@app.route("/api/dashboard")
def dashboard():
    """
    Return dashboard metrics and chart data.
    """

    return jsonify(
        get_dashboard_summary()
    )


# ============================================================
# ALERT API
# ============================================================

@app.route("/api/alerts")
def alerts():
    """
    Return correlated incident alerts.
    """

    return jsonify(
        get_alerts()
    )


# ============================================================
# EVENTS API
# ============================================================

@app.route("/api/events")
def events():
    """
    Return normalized event logs.
    """

    hostname = request.args.get(
        "hostname"
    )

    return jsonify(
        get_events(
            hostname
        )
    )


# ============================================================
# DEVICES API
# ============================================================

@app.route("/api/devices")
def devices():
    """
    Return monitored device summaries.
    """

    return jsonify(
        get_devices()
    )


# ============================================================
# INCIDENTS API
# ============================================================

@app.route("/api/incidents")
def get_incidents():
    """Fetch all incidents."""

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""
            SELECT
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
            FROM incidents
            ORDER BY timestamp DESC
        """)

        rows = cursor.fetchall()

    finally:

        conn.close()

    incidents = []

    for r in rows:

        # ----------------------------------------------------
        # Incident report
        # ----------------------------------------------------

        incident_report = None

        try:

            incident_report = (
                json.loads(
                    r["incident_report"]
                )
                if r["incident_report"]
                else None
            )

        except Exception:

            incident_report = (
                r["incident_report"]
            )

        # ----------------------------------------------------
        # Playbook
        # ----------------------------------------------------

        try:

            playbook_steps = (
                json.loads(
                    r["playbook_steps"]
                )
                if r["playbook_steps"]
                else []
            )

        except Exception:

            playbook_steps = []

        # ----------------------------------------------------
        # MITRE
        # ----------------------------------------------------

        try:

            mitre = (
                json.loads(
                    r["mitre"]
                )
                if r["mitre"]
                else {
                    "technique_id": "Unknown",
                    "technique": "Unknown",
                    "tactic": "Unknown",
                }
            )

        except Exception:

            mitre = {
                "technique_id": "Unknown",
                "technique": "Unknown",
                "tactic": "Unknown",
            }

        # ----------------------------------------------------
        # Response object
        # ----------------------------------------------------

        incidents.append({

            "incident_id":
                r["incident_id"],

            "log_id":
                r["log_id"],

            "threat_type":
                r["threat_type"],

            "hostname":
                r["hostname"],

            "os":
                r["os"],

            "source_ip":
                r["source_ip"],

            "user":
                r["user"],

            "process":
                r["process"],

            "file_path":
                r["file_path"],

            "severity":
                r["severity"],

            "timestamp":
                r["timestamp"],

            "status":
                r["status"],

            "action_taken":
                r["action_taken"],

            "command_executed":
                r["command_executed"],

            "playbook_steps":
                playbook_steps,

            "incident_report":
                incident_report,

            "ml_prediction":
                (
                    incident_report.get(
                        "ml_prediction"
                    )
                    if isinstance(
                        incident_report,
                        dict
                    )
                    else None
                ),

            "ml_confidence":
                (
                    incident_report.get(
                        "ml_confidence"
                    )
                    if isinstance(
                        incident_report,
                        dict
                    )
                    else None
                ),

            "alert_status":
                r["alert_status"],

            "mitre":
                mitre,
        })

    return jsonify(
        incidents
    )


# ============================================================
# INCIDENT RESPONSE LOGS
# ============================================================

@app.route("/api/incidents/logs")
def get_incident_logs():
    """
    Return incident response terminal logs.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                log_id,
                incident_id,
                timestamp,
                message
            FROM response_logs
            ORDER BY log_id ASC
        """)

        rows = cursor.fetchall()

    finally:

        conn.close()

    logs = []

    for r in rows:

        logs.append({

            "log_id":
                r["log_id"],

            "incident_id":
                r["incident_id"],

            "timestamp":
                r["timestamp"],

            "message":
                r["message"],
        })

    return jsonify(
        logs
    )


# ============================================================
# SUSPICIOUS ENTITIES
# ============================================================

@app.route("/api/incidents/suspicious")
def get_suspicious_entities():
    """
    Return highly suspicious IPs / hosts.
    """

    conn = get_connection()

    try:

        result = (
            incident_response
            .get_highly_suspicious_entities(
                conn
            )
        )

    finally:

        conn.close()

    return jsonify(
        result
    )


# ============================================================
# INCIDENT SETTINGS
# ============================================================

@app.route(
    "/api/incidents/settings",
    methods=[
        "GET",
        "POST",
    ]
)
def get_or_post_settings():
    """
    Read or update automated response settings.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        if request.method == "POST":

            data = (
                request.get_json(
                    silent=True
                )
                or {}
            )

            for key in [
                "auto_response_enabled",
                "simulation_mode",
            ]:

                if key in data:

                    val = (
                        "true"
                        if data[key]
                        else "false"
                    )

                    cursor.execute("""
                        INSERT OR REPLACE
                        INTO settings
                        (key, value)
                        VALUES (?, ?)
                    """, (
                        key,
                        val,
                    ))

            conn.commit()

        cursor.execute("""
            SELECT
                key,
                value
            FROM settings
        """)

        settings = {

            r["key"]:
                (
                    r["value"]
                    ==
                    "true"
                )

            for r
            in cursor.fetchall()
        }

    finally:

        conn.close()

    return jsonify(
        settings
    )


# ============================================================
# EXECUTE INCIDENT
# ============================================================

@app.route(
    "/api/incidents/execute",
    methods=["POST"]
)
def execute_incident():
    """
    Execute or simulate an incident response playbook.
    """

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    incident_id = data.get(
        "incident_id"
    )

    enforce = data.get(
        "enforce",
        False
    )

    if not incident_id:

        return jsonify({
            "error":
                "Missing incident_id"
        }), 400

    conn = get_connection()

    try:

        success = (
            incident_response
            .execute_incident_playbook(
                conn,
                incident_id,
                enforce=enforce
            )
        )

    finally:

        conn.close()

    if success:

        return jsonify({
            "success": True
        })

    return jsonify({
        "error":
            "Incident not found"
    }), 404


# ============================================================
# RESET INCIDENTS
# ============================================================

@app.route(
    "/api/incidents/reset",
    methods=["POST"]
)
def reset_incidents():
    """
    Clear incidents and response logs, then re-scan.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM incidents"
        )

        cursor.execute(
            "DELETE FROM response_logs"
        )

        conn.commit()

        incident_response.scan_and_generate_incidents(
            conn
        )

    finally:

        conn.close()

    return jsonify({
        "success": True
    })


# ============================================================
# ALERT SUMMARY
# ============================================================

@app.route("/api/alerts/summary")
def alert_summary():
    """
    Return correlation summary for one security log.
    """

    log_id = request.args.get(
        "log_id"
    )

    if not log_id:

        return jsonify({
            "error":
                "missing log_id"
        }), 400

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT *
            FROM security_logs
            WHERE log_id = ?
            """,
            (
                log_id,
            )
        )

        row = cursor.fetchone()

        if not row:

            return jsonify({
                "error":
                    "log not found"
            }), 404

        row_dict = dict(
            row
        )

        # ====================================================
        # MITRE MAPPING
        # ====================================================

        try:

            from ingestion.mitre_mapper import (
                get_mitre_mapping
            )

        except Exception:

            try:

                from backend.analyzer.ingestion.mitre_mapper import (
                    get_mitre_mapping
                )

            except Exception:

                def get_mitre_mapping(_):
                    return {
                        "technique_id":
                            "Unknown",

                        "technique":
                            "Unknown",

                        "tactic":
                            "Unknown",
                    }

        mitre = get_mitre_mapping(
            row_dict.get(
                "ml_prediction"
            )
        )

        # ====================================================
        # EVENT
        # ====================================================

        event = {

            "id":
                row_dict.get(
                    "log_id"
                ),

            "timestamp":
                row_dict.get(
                    "timestamp"
                ),

            "hostname":
                row_dict.get(
                    "hostname"
                ),

            "ip":
                row_dict.get(
                    "source_ip"
                ),

            "os":
                row_dict.get(
                    "os"
                ),

            "user":
                row_dict.get(
                    "user"
                ),

            "process":
                row_dict.get(
                    "process"
                ),

            "file_path":
                row_dict.get(
                    "file_path"
                ),

            "destination_ip":
                row_dict.get(
                    "destination_ip"
                ),

            "severity":
                row_dict.get(
                    "severity"
                ),

            "ml_prediction":
                row_dict.get(
                    "ml_prediction"
                ),

            "ml_confidence":
                row_dict.get(
                    "ml_confidence"
                ),

            "raw_log":
                row_dict.get(
                    "raw_log"
                ),

            "threat_category":
                row_dict.get(
                    "threat_category"
                ),

            "threat_score":
                row_dict.get(
                    "threat_score"
                ),
        }

        # ====================================================
        # RELATED EVENTS
        # ====================================================

        timestamp_value = (
            row_dict.get(
                "timestamp"
            )
        )

        start = None
        end = None

        try:

            ts = datetime.fromisoformat(
                str(
                    timestamp_value
                ).replace(
                    "Z",
                    "+00:00"
                )
            )

            start = (
                ts
                -
                timedelta(
                    minutes=5
                )
            ).isoformat()

            end = (
                ts
                +
                timedelta(
                    minutes=5
                )
            ).isoformat()

        except Exception:

            pass

        related = []

        if (
            start is not None
            and
            end is not None
        ):

            cursor.execute(
                """
                SELECT
                    log_id,
                    timestamp,
                    raw_log,
                    severity
                FROM security_logs
                WHERE hostname = ?
                AND timestamp BETWEEN ? AND ?
                ORDER BY timestamp ASC
                LIMIT 50
                """,
                (
                    row_dict.get(
                        "hostname"
                    ),
                    start,
                    end,
                )
            )

            for related_row in cursor.fetchall():

                rr = dict(
                    related_row
                )

                related.append({

                    "id":
                        rr.get(
                            "log_id"
                        ),

                    "timestamp":
                        rr.get(
                            "timestamp"
                        ),

                    "raw_log":
                        rr.get(
                            "raw_log"
                        ),

                    "severity":
                        rr.get(
                            "severity"
                        ),
                })

        # ====================================================
        # SIMPLE CORRELATION FINDINGS
        # ====================================================

        findings = []

        raw = (
            row_dict.get(
                "raw_log"
            )
            or ""
        ).lower()

        if (
            "failed" in raw
            and
            "login" in raw
        ):

            findings.append(
                "Multiple failed login "
                "attempts detected"
            )

        if (
            "sudo" in raw
            or
            "privilege" in raw
            or
            "elevat" in raw
        ):

            findings.append(
                "Possible privilege "
                "escalation activity"
            )

        if (
            "powershell" in raw
            or
            "cmd.exe" in raw
            or
            "rundll32" in raw
        ):

            findings.append(
                "Suspicious process execution "
                "(script interpreter)"
            )

        if not findings:

            findings.append(
                "No immediate correlation "
                "findings; inspect related logs"
            )

        result = {

            "event":
                event,

            "related":
                related,

            "findings":
                findings,

            "mitre":
                mitre,
        }

    finally:

        conn.close()

    return jsonify(
        result
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # Perform one startup classification before Flask begins
    # serving concurrent requests.
    # --------------------------------------------------------

    run_ml_classification()

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
        threaded=True
    )