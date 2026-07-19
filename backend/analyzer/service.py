import sys
from pathlib import Path

CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from database import get_connection
try:
    from backend.analyzer.ingestion.mitre_mapper import get_mitre_mapping
except ImportError:
    from ingestion.mitre_mapper import get_mitre_mapping


def get_dashboard_summary():
    """Return dashboard statistics from SQLite."""

    conn = get_connection()
    cursor = conn.cursor()

    # Total events
    cursor.execute("SELECT COUNT(*) FROM security_logs")
    total_events = cursor.fetchone()[0]

    # Total devices
    cursor.execute("SELECT COUNT(DISTINCT hostname) FROM security_logs")
    total_devices = cursor.fetchone()[0]

    # Critical threats
    cursor.execute("""
        SELECT COUNT(*)
        FROM security_logs
        WHERE UPPER(severity)='CRITICAL'
    """)
    total_threats = cursor.fetchone()[0]

    # Active alerts (Critical + High)
    cursor.execute("""
        SELECT COUNT(*)
        FROM security_logs
        WHERE UPPER(severity) IN ('CRITICAL','HIGH')
    """)
    total_alerts = cursor.fetchone()[0]

    # Severity distribution
    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM security_logs
        GROUP BY severity
    """)

    severity_rows = cursor.fetchall()

    cursor.execute("""
        SELECT ml_prediction, COUNT(*) AS total, ROUND(AVG(COALESCE(ml_confidence, 0)), 2) AS avg_confidence
        FROM security_logs
        GROUP BY ml_prediction
        ORDER BY total DESC
        LIMIT 1
    """)

    ml_row = cursor.fetchone()
    dominant_prediction = ml_row["ml_prediction"] if ml_row else "UNKNOWN"
    dominant_confidence = ml_row["avg_confidence"] if ml_row else 0.0
    dominant_count = ml_row["total"] if ml_row else 0
    dominant_mitre = get_mitre_mapping(dominant_prediction)

    distribution_labels = []
    distribution_values = []

    for row in severity_rows:
        distribution_labels.append(row["severity"])
        distribution_values.append(row["COUNT(*)"])

    # Timeline (group by hour)
    cursor.execute("""
        SELECT
            strftime('%H:00', timestamp) AS hour,
            COUNT(*) AS total
        FROM security_logs
        GROUP BY hour
        ORDER BY hour
    """)

    timeline_rows = cursor.fetchall()

    timeline_labels = []
    timeline_values = []

    for row in timeline_rows:
        timeline_labels.append(row["hour"])
        timeline_values.append(row["total"])

    conn.close()

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
            "prediction": dominant_prediction or "UNKNOWN",
            "confidence": dominant_confidence,
            "count": dominant_count,
            "mitre": dominant_mitre,
        },
    }


def get_events():
    """Return event logs."""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            log_id,
            timestamp,
            hostname,
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
            "id": row["log_id"],
            "timestamp": row["timestamp"],
            "hostname": row["hostname"],
            "ip": row["source_ip"],
            "severity": row["severity"],
            "event": row["raw_log"],
            "ml_prediction": row["ml_prediction"],
            "threat_level": row["threat_level"],
            "threat_score": row["threat_score"],
            "threat_category": row["threat_category"],
        })

    return events


def get_alerts():
    """Return latest Critical and High alerts."""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            log_id,
            severity,
            hostname,
            raw_log,
            timestamp
        FROM security_logs
        WHERE UPPER(severity) IN ('CRITICAL', 'HIGH')
        ORDER BY timestamp DESC
        LIMIT 5
    """)

    rows = cursor.fetchall()
    conn.close()

    alerts = []

    for row in rows:
        alerts.append({
            "id": row["log_id"],
            "severity": row["severity"],
            "title": row["raw_log"],
            "device": row["hostname"],
            "time": row["timestamp"]
        })

    return alerts