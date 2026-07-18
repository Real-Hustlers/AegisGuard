import sys
from pathlib import Path

from flask import Flask, jsonify, render_template

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))

try:
    from service import get_alerts, get_dashboard_summary, get_events
    from ingestion.classifier import classify_logs
    from mysql.merge_log_sql import import_classified_logs_to_db
except ImportError:
    from backend.analyzer.service import get_alerts, get_dashboard_summary, get_events
    from backend.analyzer.ingestion.classifier import classify_logs
    from mysql.merge_log_sql import import_classified_logs_to_db

app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))


def run_ml_classification():
    """Classify merged logs with the trained ML model when the backend starts."""
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
    return jsonify(get_events())


run_ml_classification()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)