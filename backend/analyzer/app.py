import sys
import json
import os
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta

from flask import (
    Flask,
    g,
    jsonify,
    render_template,
    request,
)

from backend.deployment.runtime_paths import (
    resolve_analyzer_data_dir,
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
    Return a writable Analyzer runtime path.

    Source mode keeps the repository-root layout.

    Frozen enterprise deployments use AEGISGUARD_DATA_DIR or
    %ProgramData%\\AegisGuard\\Analyzer.
    """

    base_path = (
        resolve_analyzer_data_dir()
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

from backend.platform.data_privacy import redact_sensitive_text

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

    from backend.analyzer.database import (
        build_log_identity,
        get_connection,
        get_database_path,
        get_existing_log_ids,
        insert_new_security_logs,
        record_collector_endpoint,
    )

except ImportError:

    from database import (
        build_log_identity,
        get_connection,
        get_database_path,
        get_existing_log_ids,
        insert_new_security_logs,
        record_collector_endpoint,
    )


try:

    import incident_response

except ImportError:

    from backend.analyzer import (
        incident_response
    )


try:

    from ingestion.classifier import (
        classify_logs,
        classify_records,
        warm_up_classifier,
    )

except ImportError:

    try:

        from backend.analyzer.ingestion.classifier import (
            classify_logs,
            classify_records,
            warm_up_classifier,
        )

    except Exception as e:

        debug_print(
            "Classifier import failed: "
            f"{redact_sensitive_text(e)}"
        )

        classify_logs = None
        classify_records = None
        warm_up_classifier = None


try:
    from backend.analyzer.soar import (
        ApprovalDeniedError,
        RecoveryDeniedError,
        SoarEngine,
    )
except ImportError:
    from soar import (
        ApprovalDeniedError,
        RecoveryDeniedError,
        SoarEngine,
    )


try:
    from backend.analyzer.collector_api import create_collector_blueprint
except ImportError:
    from collector_api import create_collector_blueprint

try:
    from backend.analyzer.auth_api import create_auth_blueprint
except ImportError:
    from auth_api import create_auth_blueprint

try:
    from backend.analyzer.app_authorization import (
        install_application_authorization,
    )
except ImportError:
    from app_authorization import install_application_authorization

try:
    from backend.analyzer.audit_context import (
        install_request_correlation,
    )
except ImportError:
    from audit_context import install_request_correlation

try:
    from backend.analyzer.audit_api import create_audit_blueprint
except ImportError:
    from audit_api import create_audit_blueprint

try:
    from backend.analyzer.incident_api import create_incident_blueprint
    from backend.analyzer.incident_service import list_incidents
except ImportError:
    from incident_api import create_incident_blueprint
    from incident_service import list_incidents

try:
    from backend.analyzer.asset_api import (
        create_asset_management_blueprint,
    )
except ImportError:
    from asset_api import (
        create_asset_management_blueprint,
    )

try:
    from backend.analyzer.browser_security import (
        install_browser_security_headers,
    )
except ImportError:
    from browser_security import install_browser_security_headers

try:
    from backend.analyzer.sensitive_audit import (
        install_sensitive_operation_auditing,
    )
except ImportError:
    from sensitive_audit import install_sensitive_operation_auditing

try:
    from backend.analyzer.privacy_projection import (
        install_application_privacy_projection,
    )
except ImportError:
    from privacy_projection import install_application_privacy_projection

try:
    from backend.analyzer.intelligence.api import create_intelligence_blueprint
    from backend.analyzer.intelligence.ml_runtime import (
        create_configured_ml_runtime_provider,
    )
except ImportError:
    from intelligence.api import create_intelligence_blueprint
    from intelligence.ml_runtime import (
        create_configured_ml_runtime_provider,
    )

try:
    from backend.analyzer.ingest_pipeline import process_normalized_collector_logs
except ImportError:
    from ingest_pipeline import process_normalized_collector_logs

try:
    from backend.analyzer.ingest_worker import start_default_ingest_worker_thread
except ImportError:
    from ingest_worker import start_default_ingest_worker_thread

app.register_blueprint(
    create_collector_blueprint(
        get_connection,
        auth_required=True,
        enrollment_token=os.environ.get(
            "AEGISGUARD_COLLECTOR_ENROLLMENT_TOKEN"
        ),
        recovery_token=os.environ.get(
            "AEGISGUARD_COLLECTOR_RECOVERY_TOKEN"
        ),
        mtls_required=(
            os.environ.get(
                "AEGISGUARD_COLLECTOR_MTLS_REQUIRED",
                "false",
            ).strip().lower()
            in {"1", "true", "yes", "on"}
        ),
    )
)


app.register_blueprint(
    create_auth_blueprint(
        get_connection,
        cookie_secure=(
            os.environ.get(
                "AEGISGUARD_SESSION_COOKIE_SECURE",
                "true",
            ).strip().lower()
            in {"1", "true", "yes", "on"}
        ),
        session_ttl_seconds=int(
            os.environ.get(
                "AEGISGUARD_SESSION_TTL_SECONDS",
                str(8 * 60 * 60),
            )
        ),
        session_idle_timeout_seconds=int(
            os.environ.get(
                "AEGISGUARD_SESSION_IDLE_TIMEOUT_SECONDS",
                str(30 * 60),
            )
        ),
        login_failure_limit=int(
            os.environ.get("AEGISGUARD_LOGIN_FAILURE_LIMIT", "5")
        ),
        login_window_seconds=int(
            os.environ.get(
                "AEGISGUARD_LOGIN_WINDOW_SECONDS",
                str(5 * 60),
            )
        ),
        login_block_seconds=int(
            os.environ.get(
                "AEGISGUARD_LOGIN_BLOCK_SECONDS",
                str(5 * 60),
            )
        ),
    )
)


governed_ml_runtime_provider = (
    create_configured_ml_runtime_provider(
        default_registry_root=app_data_path(
            "data/ml_registry"
        ),
    )
)


app.register_blueprint(
    create_intelligence_blueprint(
        get_connection,
        ml_runtime_provider=governed_ml_runtime_provider,
    )
)

app.register_blueprint(
    create_audit_blueprint(
        get_connection,
        retention_days=int(
            os.environ.get(
                "AEGISGUARD_AUDIT_RETENTION_DAYS",
                "365",
            )
        ),
    )
)

app.register_blueprint(
    create_incident_blueprint(
        get_connection,
    )
)

app.register_blueprint(
    create_asset_management_blueprint(
        get_connection,
        stale_after_seconds=float(
            os.environ.get(
                "AEGISGUARD_COLLECTOR_STALE_AFTER_SECONDS",
                "90",
            )
        ),
    )
)


install_request_correlation(app)

install_application_authorization(
    app,
    get_connection,
    session_idle_timeout_seconds=int(
        os.environ.get(
            "AEGISGUARD_SESSION_IDLE_TIMEOUT_SECONDS",
            str(30 * 60),
        )
    ),
)

install_application_privacy_projection(app)

install_sensitive_operation_auditing(
    app,
    get_connection,
    retention_days=int(
        os.environ.get(
            "AEGISGUARD_AUDIT_RETENTION_DAYS",
            "365",
        )
    ),
)

install_browser_security_headers(app)


if warm_up_classifier is not None:
    # Model deserialization can take seconds on a Windows endpoint. Do it once
    # before Flask starts accepting Collector requests, never in the hot path.
    warm_up_classifier()


debug_print(
    "[AegisGuard] Runtime mode: "
    f"{'frozen' if getattr(sys, 'frozen', False) else 'source'}"
)
debug_print(f"[AegisGuard] Database path: {get_database_path()}")


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


@app.after_request
def disable_api_caching(response):
    """Polling clients must always receive the current SQLite state."""

    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


def _normalize_uploaded_logs(payload):
    """Normalize one Collector payload without touching historical files."""

    logs = payload.get("logs", [])
    if not isinstance(logs, list):
        raise ValueError("'logs' must be a list")

    machine_id = str(payload.get("machine_id") or payload.get("hostname") or "UNKNOWN")
    hostname = str(payload.get("hostname") or machine_id)
    operating_system = str(payload.get("os") or "Windows")
    normalized = []

    for raw in logs:
        if not isinstance(raw, dict):
            continue

        record_id = raw.get("record_id", raw.get("RecordId"))
        event = {
            "machine_id": str(raw.get("machine_id") or machine_id),
            "hostname": str(raw.get("hostname") or raw.get("MachineName") or hostname),
            "os": str(raw.get("os") or operating_system),
            "record_id": record_id,
            "timestamp": raw.get("timestamp") or raw.get("TimeCreated") or "",
            "event_type": str(raw.get("event_type") or raw.get("event_id") or raw.get("Id") or "OTHER").upper(),
            "user": raw.get("user") or raw.get("User") or "",
            "source_ip": raw.get("source_ip") or raw.get("SourceIp") or "",
            "destination_ip": raw.get("destination_ip") or raw.get("DestinationIp") or "",
            "process": raw.get("process") or raw.get("ProcessName") or "",
            "file_path": raw.get("file_path") or raw.get("FilePath") or "",
            "severity": raw.get("severity") or raw.get("LevelDisplayName") or "INFO",
            "raw_log": raw.get("raw_log") or raw.get("Message") or "",
        }
        normalized.append(event)

    return machine_id, normalized


def _ingest_live_batch(payload, collector_ip=None):
    """Fast, retry-safe Collector ingestion path.

    The old JSON merge/classify/import/correlation workflow remains available
    for manual historical processing, but it is deliberately not in this HTTP
    request path.  SQLite is the running Analyzer's canonical source of truth.
    """

    started = time.perf_counter()
    try:
        machine_id, normalized = _normalize_uploaded_logs(payload)
    except ValueError as exc:
        return jsonify({
            "status": "error",
            "message": str(exc),
            "machine": payload.get("machine_id", "UNKNOWN"),
        }), 400

    try:
        result = process_normalized_collector_logs(
            machine_id,
            normalized,
            collector_ip,
        )
    except Exception as exc:
        safe_error = redact_sensitive_text(exc)
        debug_print(
            f"[INGEST] Batch failed for {machine_id}: {safe_error}"
        )
        return jsonify({
            "status": "error",
            "message": "Analyzer ingestion failed",
            "machine": machine_id,
            "logs_received": len(normalized),
        }), 500

    inserted_ids = set(result["inserted_log_ids"])
    for log in normalized:
        identity = build_log_identity(log)
        debug_print(
            f"[INGEST] hostname={log['hostname']} record_id={log['record_id']} "
            f"identity={identity} inserted={identity in inserted_ids} "
            f"database={get_database_path()}"
        )

    elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
    debug_print(
        f"[INGEST] machine={machine_id} received={len(normalized)} "
        f"new={result['new_logs_added']} elapsed_ms={elapsed_ms}"
    )
    return jsonify({
        "status": "success",
        "machine": machine_id,
        "logs_received": len(normalized),
        "new_logs_added": result["new_logs_added"],
        "processing_ms": elapsed_ms,
    }), 200


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
            Ã¢â€ â€œ
        windows_logs.json
            Ã¢â€ â€œ
        merge_logs()
            Ã¢â€ â€œ
        classifier
            Ã¢â€ â€œ
        SQLite
            Ã¢â€ â€œ
        correlation engine

    Only one upload may execute this pipeline at a time.
    """

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    return _ingest_live_batch(data, request.remote_addr)

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
                            f"{redact_sensitive_text(backup_error)}"
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
            f"is invalid: {redact_sensitive_text(e)}"
        )

    except Exception as e:

        debug_print(
            "Startup classification error: "
            f"{redact_sensitive_text(e)}"
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
    """Fetch unified incident summaries with legacy-compatible fields."""

    conn = get_connection()
    try:
        incidents = list_incidents(
            conn,
            limit=500,
        )
    finally:
        conn.close()

    return jsonify(incidents)


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
                "soar_dry_run",
                "soar_allow_private_ip_blocking",
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

            if "soar_mode" in data:
                mode = str(data["soar_mode"]).upper()
                if mode not in {"OFF", "MANUAL", "AUTO"}:
                    return jsonify({"error": "soar_mode must be OFF, MANUAL, or AUTO"}), 400
                cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("soar_mode", mode))

            if "soar_auto_min_score" in data:
                try:
                    score = int(data["soar_auto_min_score"])
                except (TypeError, ValueError):
                    return jsonify({"error": "soar_auto_min_score must be an integer"}), 400
                if not 0 <= score <= 100:
                    return jsonify({"error": "soar_auto_min_score must be between 0 and 100"}), 400
                cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("soar_auto_min_score", str(score)))

            if "soar_allowlist" in data:
                allowlist = data["soar_allowlist"]
                if not isinstance(allowlist, list) or not all(isinstance(item, str) for item in allowlist):
                    return jsonify({"error": "soar_allowlist must be a list of IP strings"}), 400
                cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ("soar_allowlist", json.dumps(allowlist)))

            conn.commit()

        cursor.execute("""
            SELECT
                key,
                value
            FROM settings
        """)

        boolean_settings = {"auto_response_enabled", "simulation_mode", "soar_dry_run", "soar_allow_private_ip_blocking"}
        settings = {}
        for r in cursor.fetchall():
            value = r["value"]
            if r["key"] in boolean_settings:
                value = value == "true"
            elif r["key"] == "soar_auto_min_score":
                value = int(value)
            elif r["key"] == "soar_allowlist":
                try:
                    value = json.loads(value)
                except (TypeError, json.JSONDecodeError):
                    value = []
            settings[r["key"]] = value

    finally:

        conn.close()

    return jsonify(
        settings
    )


# ============================================================
# SAFE SOAR RESPONSE API (Analyzer-side only)
# ============================================================

def _soar_incident_from_payload(data):
    """Resolve an optional incident; clients never supply commands or scope."""
    incident_id = data.get("incident_id")
    if not incident_id:
        return {"incident_id": "manual", "hostname": "ANALYZER", "log_id": None,
                "severity": "MANUAL", "threat_score": 0, "source_ip": data.get("ip")}
    conn = get_connection()
    try:
        row = conn.execute("""
            SELECT incident_id, log_id, hostname, source_ip, severity, threat_type
            FROM incidents WHERE incident_id = ?
        """, (incident_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return dict(row)


@app.route("/api/response-actions")
def get_response_actions():
    conn = get_connection()
    try:
        return jsonify(SoarEngine(conn).list_actions(request.args.get("limit", 50)))
    finally:
        conn.close()


@app.route("/api/response-actions/<int:action_id>")
def get_response_action(action_id):
    conn = get_connection()
    try:
        action = SoarEngine(conn).get_action(action_id)
        return (jsonify(action), 200) if action else (jsonify({"error": "response action not found"}), 404)
    finally:
        conn.close()


def _trusted_response_user_id():
    user = getattr(g, "aegisguard_user", None) or {}
    return str(user.get("user_id") or "").strip() or None


@app.route("/api/response-actions/<int:action_id>/approve", methods=["POST"])
def approve_response_action(action_id):
    conn = get_connection()
    try:
        action = SoarEngine(conn).approve(
            action_id,
            approved_by_user_id=_trusted_response_user_id(),
        )
        return (
            (jsonify(action), 200)
            if action
            else (
                jsonify({
                    "error": "response action not found",
                }),
                404,
            )
        )
    except ApprovalDeniedError as exc:
        return jsonify({
            "status": "error",
            "error": exc.code,
            "message": str(exc),
            "action_id": action_id,
        }), 403
    finally:
        conn.close()


@app.route(
    "/api/response-actions/<int:action_id>/reconcile",
    methods=["POST"],
)
def reconcile_response_action(action_id):
    conn = get_connection()
    try:
        action = SoarEngine(conn).reconcile(
            action_id,
            reconciled_by_user_id=_trusted_response_user_id(),
        )
        return (
            (jsonify(action), 200)
            if action
            else (
                jsonify({
                    "error": "response action not found",
                }),
                404,
            )
        )
    except RecoveryDeniedError as exc:
        return jsonify({
            "status": "error",
            "error": exc.code,
            "message": str(exc),
            "action_id": action_id,
        }), 403
    finally:
        conn.close()


@app.route("/api/soar/block-ip", methods=["POST"])
def soar_block_ip():
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get("ip"), str) or not data["ip"].strip():
        return jsonify({"error": "ip is required"}), 400
    incident = _soar_incident_from_payload(data)
    if incident is None:
        return jsonify({"error": "incident not found"}), 404
    conn = get_connection()
    try:
        action = SoarEngine(conn).request_block(
            incident,
            data["ip"],
            data.get("reason"),
            requested_by_user_id=_trusted_response_user_id(),
        )
        return jsonify(action)
    finally:
        conn.close()


@app.route("/api/soar/unblock-ip", methods=["POST"])
def soar_unblock_ip():
    data = request.get_json(silent=True) or {}
    if not isinstance(data.get("ip"), str) or not data["ip"].strip():
        return jsonify({"error": "ip is required"}), 400
    conn = get_connection()
    try:
        return jsonify(
            SoarEngine(conn).unblock(
                data["ip"],
                data.get(
                    "reason",
                    "operator requested rollback",
                ),
                rollback_by_user_id=_trusted_response_user_id(),
            )
        )
    finally:
        conn.close()


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

    # This legacy endpoint predates the constrained SOAR engine and stored
    # generic playbook commands.  It remains available for its simulation
    # dashboard/tests, but live host command execution is intentionally not
    # exposed through the API.  Use /api/soar/block-ip for the only supported
    # real response action.
    if enforce:
        return jsonify({
            "error": "legacy live playbook execution is disabled; use the safe SOAR IP action"
        }), 403

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

    if (
        os.environ.get(
            "AEGISGUARD_COLLECTOR_MTLS_REQUIRED",
            "false",
        ).strip().lower()
        in {"1", "true", "yes", "on"}
    ):
        raise RuntimeError(
            "collector mTLS mode cannot use the direct Flask server; "
            "start backend.analyzer.mtls_server instead"
        )

    # The Collector hot path performs incremental classification and SQLite
    # persistence.  Do not replay legacy JSON history at startup: it can be
    # large, delays availability, and uses a different historical identity.

    (
        _ingest_worker,
        _ingest_thread,
        _ingest_stop_event,
        _recovered_batches,
    ) = start_default_ingest_worker_thread(
        get_connection,
    )

    debug_print(
        f"[INGEST WORKER] started; recovered={_recovered_batches}"
    )

    try:
        app.run(
            host="0.0.0.0",
            port=5000,
            debug=False,
            use_reloader=False,
            threaded=True
        )
    finally:
        _ingest_stop_event.set()
        _ingest_thread.join(timeout=5)
