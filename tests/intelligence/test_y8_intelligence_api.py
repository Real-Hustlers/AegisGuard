import sqlite3
from pathlib import Path

from flask import Flask

from backend.analyzer.intelligence.api import create_intelligence_blueprint


SCHEMA = """
CREATE TABLE security_logs (
    log_id TEXT,
    timestamp TEXT,
    event_type TEXT,
    severity TEXT,
    hostname TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    user TEXT,
    process TEXT,
    file_path TEXT,
    raw_log TEXT,
    ml_prediction TEXT,
    ml_confidence REAL,
    threat_level TEXT,
    threat_score INTEGER,
    threat_category TEXT
)
"""


def connection_factory(path: Path):
    def factory():
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn
    return factory


def insert_event(path: Path, *, log_id: str, event_type: str, timestamp: str):
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            INSERT INTO security_logs VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                log_id,
                timestamp,
                event_type,
                "HIGH",
                "Y8-API-HOST",
                "10.0.0.5",
                "10.0.0.10",
                "alice",
                "powershell.exe",
                None,
                event_type,
                "BRUTE_FORCE" if event_type == "FAILED_LOGIN" else "NORMAL",
                96.0,
                "HIGH",
                80,
                "Test",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def make_client(tmp_path):
    db_path = tmp_path / "intelligence-api.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(SCHEMA)
        conn.commit()
    finally:
        conn.close()

    app = Flask(__name__)
    app.register_blueprint(
        create_intelligence_blueprint(connection_factory(db_path))
    )
    return app.test_client(), db_path


def test_get_intelligence_returns_real_read_only_snapshot(tmp_path):
    client, db_path = make_client(tmp_path)
    insert_event(
        db_path,
        log_id="EVT-1",
        event_type="FAILED_LOGIN",
        timestamp="2026-09-22T10:00:00Z",
    )

    response = client.get("/api/intelligence")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["snapshot_version"] == "intelligence-snapshot-v1"
    assert payload["detection_counts"]["RULE"] == 1
    assert payload["governance"]["read_only"] is True
    assert payload["governance"]["writes_database"] is False


def test_event_limit_query_is_applied(tmp_path):
    client, db_path = make_client(tmp_path)
    for index in range(3):
        insert_event(
            db_path,
            log_id=f"EVT-{index}",
            event_type="LOGON_SUCCESS",
            timestamp=f"2026-09-22T10:0{index}:00Z",
        )

    payload = client.get("/api/intelligence?event_limit=1").get_json()

    assert payload["scope"]["event_limit"] == 1
    assert payload["scope"]["events_analyzed"] == 1
    assert payload["scope"]["total_events"] == 3
    assert payload["scope"]["truncated"] is True


def test_invalid_event_limit_returns_400(tmp_path):
    client, _ = make_client(tmp_path)

    response = client.get("/api/intelligence?event_limit=0")

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_event_limit"


def test_intelligence_endpoint_is_get_only(tmp_path):
    client, _ = make_client(tmp_path)
    assert client.post("/api/intelligence").status_code == 405


def test_main_analyzer_registers_intelligence_blueprint():
    app_source = (
        Path(__file__).resolve().parents[2]
        / "backend"
        / "analyzer"
        / "app.py"
    ).read_text(encoding="utf-8")

    assert "create_intelligence_blueprint" in app_source
    assert "create_intelligence_blueprint(get_connection)" in app_source
