import sys
import json
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent

if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))


try:
    from backend.analyzer.database import get_connection
except ImportError:
    from database import get_connection

try:
    from backend.analyzer.ingestion.mitre_mapper import get_mitre_mapping
except ImportError:
    from ingestion.mitre_mapper import get_mitre_mapping


# =========================================================
# DASHBOARD SUMMARY
# =========================================================

def get_dashboard_summary():
    """Return dashboard statistics from SQLite."""

    conn = get_connection()
    cursor = conn.cursor()

    # =====================================================
    # TOTAL EVENTS
    # Source: security_logs
    # =====================================================

    cursor.execute("""
        SELECT COUNT(*)
        FROM security_logs
    """)

    total_events = cursor.fetchone()[0]

    # =====================================================
    # TOTAL DEVICES
    # Source: security_logs
    # =====================================================

    cursor.execute("""
        SELECT COUNT(DISTINCT hostname)
        FROM security_logs
        WHERE hostname IS NOT NULL
        AND hostname != ''
    """)

    total_devices = cursor.fetchone()[0]

    # =====================================================
    # TOTAL THREATS
    #
    # A threat here means an OPEN correlated incident.
    # Source: incidents
    # =====================================================

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE UPPER(status) = 'OPEN'
    """)

    total_threats = cursor.fetchone()[0]

    # =====================================================
    # ACTIVE ALERTS
    #
    # HIGH / CRITICAL incidents whose alert status
    # is still pending.
    # =====================================================

    cursor.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE UPPER(severity) IN (
            'CRITICAL',
            'HIGH'
        )
        AND (
            alert_status IS NULL
            OR UPPER(alert_status) = 'PENDING'
        )
    """)

    total_alerts = cursor.fetchone()[0]

    # =====================================================
    # EVENT SEVERITY DISTRIBUTION
    # Source: security_logs
    # =====================================================

    cursor.execute("""
        SELECT
            severity,
            COUNT(*) AS total
        FROM security_logs
        GROUP BY severity
        ORDER BY total DESC
    """)

    severity_rows = cursor.fetchall()

    distribution_labels = []
    distribution_values = []

    for row in severity_rows:

        distribution_labels.append(
            row["severity"] or "Unknown"
        )

        distribution_values.append(
            row["total"]
        )

    # =====================================================
    # DOMINANT ML PREDICTION
    # Source: security_logs
    # =====================================================

    cursor.execute("""
        SELECT
            ml_prediction,
            COUNT(*) AS total,
            ROUND(
                AVG(
                    COALESCE(
                        ml_confidence,
                        0
                    )
                ),
                2
            ) AS avg_confidence
        FROM security_logs
        GROUP BY ml_prediction
        ORDER BY total DESC
        LIMIT 1
    """)

    ml_row = cursor.fetchone()

    if ml_row:

        dominant_prediction = (
            ml_row["ml_prediction"]
            or "UNKNOWN"
        )

        dominant_confidence = (
            ml_row["avg_confidence"]
            or 0.0
        )

        dominant_count = (
            ml_row["total"]
            or 0
        )

    else:

        dominant_prediction = "UNKNOWN"
        dominant_confidence = 0.0
        dominant_count = 0

    dominant_mitre = get_mitre_mapping(
        dominant_prediction
    )

    # =====================================================
    # EVENT TIMELINE
    # Source: security_logs
    # =====================================================

    cursor.execute("""
        SELECT
            strftime(
                '%H:00',
                timestamp
            ) AS hour,
            COUNT(*) AS total
        FROM security_logs
        GROUP BY hour
        ORDER BY hour
    """)

    timeline_rows = cursor.fetchall()

    timeline_labels = []
    timeline_values = []

    for row in timeline_rows:

        timeline_labels.append(
            row["hour"] or "Unknown"
        )

        timeline_values.append(
            row["total"]
        )

    conn.close()

    # =====================================================
    # DASHBOARD RESPONSE
    # =====================================================

    return {
        "events": total_events,
        "threats": total_threats,
        "devices": total_devices,
        "alerts": total_alerts,

        "timeline": {
            "labels": timeline_labels,
            "values": timeline_values,
        },

        "distribution": {
            "labels": distribution_labels,
            "values": distribution_values,
        },

        "ml_summary": {
            "prediction": dominant_prediction,
            "confidence": dominant_confidence,
            "count": dominant_count,
            "mitre": dominant_mitre,
        },
    }


# =========================================================
# EVENTS
# =========================================================

def get_events(hostname=None):
    """
    Return security event logs.

    If hostname is supplied,
    only events from that host are returned.
    """

    conn = get_connection()
    cursor = conn.cursor()

    if hostname:

        cursor.execute("""
            SELECT
                log_id,
                record_id,
                timestamp,
                hostname,
                event_type,
                user,
                source_ip,
                severity,
                raw_log,
                ml_prediction,
                threat_level,
                threat_score,
                threat_category
            FROM security_logs
            WHERE hostname = ?
            ORDER BY timestamp DESC
        """, (hostname,))

    else:

        cursor.execute("""
            SELECT
                log_id,
                record_id,
                timestamp,
                hostname,
                event_type,
                user,
                source_ip,
                severity,
                raw_log,
                ml_prediction,
                threat_level,
                threat_score,
                threat_category
            FROM security_logs
            ORDER BY timestamp DESC
        """)

    rows = cursor.fetchall()

    conn.close()

    events = []

    for row in rows:

        events.append({

            "id":
                row["log_id"],

            "record_id":
                row["record_id"],

            "timestamp":
                row["timestamp"],

            "hostname":
                row["hostname"],

            "event_type":
                row["event_type"],

            "user":
                row["user"],

            "ip":
                row["source_ip"],

            "severity":
                row["severity"],

            "event":
                row["raw_log"],

            "ml_prediction":
                row["ml_prediction"],

            "threat_level":
                row["threat_level"],

            "threat_score":
                row["threat_score"],

            "threat_category":
                row["threat_category"],
        })

    return events


# =========================================================
# ALERTS
# =========================================================

def get_alerts():
    """
    Return latest active incident alerts.

    Alerts come from correlated incidents,
    not directly from individual security logs.
    """

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            incident_id,
            threat_type,
            severity,
            hostname,
            source_ip,
            user,
            timestamp,
            status,
            alert_status,
            mitre
        FROM incidents
        WHERE UPPER(severity) IN (
            'CRITICAL',
            'HIGH'
        )
        AND (
            alert_status IS NULL
            OR UPPER(alert_status) = 'PENDING'
        )
        ORDER BY timestamp DESC
        LIMIT 10
    """)

    rows = cursor.fetchall()

    conn.close()

    alerts = []

    for row in rows:

        # -------------------------------------------------
        # Parse MITRE mapping
        # -------------------------------------------------

        mitre = {}

        try:

            if row["mitre"]:

                mitre = json.loads(
                    row["mitre"]
                )

        except Exception:

            mitre = {}

        # -------------------------------------------------
        # Build dashboard alert
        # -------------------------------------------------

        alerts.append({

            "id":
                row["incident_id"],

            "incident_id":
                row["incident_id"],

            "severity":
                row["severity"],

            "title":
                row["threat_type"],

            "device":
                row["hostname"]
                or "UNKNOWN",

            "hostname":
                row["hostname"]
                or "UNKNOWN",

            "source_ip":
                row["source_ip"],

            "user":
                row["user"],

            "time":
                row["timestamp"],

            "status":
                row["status"],

            "alert_status":
                row["alert_status"],

            "mitre":
                mitre,
        })

    return alerts


# =========================================================
# DEVICES
# =========================================================

def get_devices():
    """Return monitored device summaries from security logs."""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            hostname,
            source_ip,
            os,
            COUNT(*) AS event_count,
            MAX(timestamp) AS last_seen,
            MAX(
                CASE
                    WHEN UPPER(severity) = 'CRITICAL' THEN 3
                    WHEN UPPER(severity) = 'HIGH' THEN 2
                    ELSE 1
                END
            ) AS severity_rank
        FROM security_logs
        GROUP BY hostname
        ORDER BY severity_rank DESC, last_seen DESC
    """)

    rows = cursor.fetchall()

    conn.close()

    devices = []

    for row in rows:

        if row["severity_rank"] == 3:

            status = "critical"

        elif row["severity_rank"] == 2:

            status = "warning"

        else:

            status = "normal"

        devices.append({

            "hostname":
                row["hostname"]
                or "Unknown",

            "ip":
                row["source_ip"]
                or "Unknown",

            "os":
                row["os"]
                or "Unknown",

            "event_count":
                row["event_count"],

            "last_seen":
                row["last_seen"],

            "status":
                status,
        })

    return devices
