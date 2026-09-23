import sqlite3

from flask import Flask

from backend.analyzer.intelligence.api import create_intelligence_blueprint
from backend.analyzer.intelligence.service import MAX_EVENT_LIMIT


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


def connection_factory(path):
    def factory():
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        return conn
    return factory


def make_client(tmp_path):
    db_path = tmp_path / "y10-api.db"

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(SCHEMA)
        conn.commit()
    finally:
        conn.close()

    app = Flask(__name__)
    app.register_blueprint(
        create_intelligence_blueprint(
            connection_factory(db_path)
        )
    )

    return app.test_client(), db_path


def insert_event(db_path, n):
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO security_logs VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                f"Y10-{n}",
                f"2026-09-23T10:00:{n:02d}Z",
                "LOGON_SUCCESS",
                "INFO",
                "Y10-HOST",
                "10.0.0.5",
                None,
                "alice",
                None,
                None,
                "successful login",
                "NORMAL",
                99.0,
                "LOW",
                10,
                "Authentication",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_empty_database_returns_valid_read_only_snapshot(tmp_path):
    client, _ = make_client(tmp_path)

    response = client.get("/api/intelligence")

    assert response.status_code == 200

    payload = response.get_json()

    assert payload["scope"]["events_analyzed"] == 0
    assert payload["scope"]["total_events"] == 0
    assert payload["scope"]["truncated"] is False

    assert payload["detection_counts"] == {
        "RULE": 0,
        "ML": 0,
        "CORRELATION": 0,
    }

    assert payload["findings"] == {
        "rule": [],
        "ml": [],
        "correlation": [],
    }

    assert payload["mitre_coverage"] == []
    assert payload["attack_stories"] == []

    assert payload["governance"]["read_only"] is True
    assert payload["governance"]["writes_database"] is False


def test_api_caps_event_limit_to_maximum(tmp_path):
    client, db_path = make_client(tmp_path)

    insert_event(db_path, 1)

    response = client.get(
        f"/api/intelligence?event_limit={MAX_EVENT_LIMIT + 500}"
    )

    assert response.status_code == 200

    payload = response.get_json()

    assert payload["scope"]["event_limit"] == MAX_EVENT_LIMIT
    assert payload["scope"]["events_analyzed"] == 1
    assert payload["scope"]["total_events"] == 1


def test_non_integer_event_limit_returns_structured_400(tmp_path):
    client, _ = make_client(tmp_path)

    response = client.get(
        "/api/intelligence?event_limit=not-a-number"
    )

    assert response.status_code == 400

    payload = response.get_json()

    assert payload["error"] == "invalid_event_limit"
    assert "integer" in payload["message"]


def test_intelligence_get_does_not_modify_security_logs(tmp_path):
    client, db_path = make_client(tmp_path)

    insert_event(db_path, 1)
    insert_event(db_path, 2)

    conn = sqlite3.connect(db_path)
    before = conn.execute(
        "SELECT COUNT(*) FROM security_logs"
    ).fetchone()[0]
    conn.close()

    response = client.get(
        "/api/intelligence?event_limit=1"
    )

    assert response.status_code == 200

    conn = sqlite3.connect(db_path)
    after = conn.execute(
        "SELECT COUNT(*) FROM security_logs"
    ).fetchone()[0]
    conn.close()

    assert before == 2
    assert after == before
