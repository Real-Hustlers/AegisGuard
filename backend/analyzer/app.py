from pathlib import Path

from flask import Flask, jsonify, render_template

from service import get_alerts, get_dashboard_summary, get_events

BASE_DIR = Path(__file__).resolve().parent.parent.parent
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"))


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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)