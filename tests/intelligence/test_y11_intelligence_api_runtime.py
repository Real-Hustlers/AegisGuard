import sqlite3

from flask import Flask

from backend.analyzer.intelligence import (
    GovernedMLRuntime,
    GovernedMLRuntimeStatus,
    get_intelligence_snapshot,
)
from backend.analyzer.intelligence.api import (
    create_intelligence_blueprint,
)


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


def unavailable_runtime():
    return GovernedMLRuntime(
        status=GovernedMLRuntimeStatus.UNAVAILABLE,
        available=False,
        model_name="aegis-threat-classifier",
        reason="no promoted model",
    )


def test_api_passes_runtime_provider_to_snapshot_getter():
    runtime = unavailable_runtime()
    observed = {
        "provider_calls": 0,
    }

    def provider():
        observed["provider_calls"] += 1
        return runtime

    def snapshot_getter(
        get_connection,
        *,
        event_limit=None,
        ml_runtime=None,
    ):
        observed["event_limit"] = event_limit
        observed["runtime"] = ml_runtime

        return {
            "governed_ml_runtime": ml_runtime.to_dict(),
        }

    app = Flask(__name__)
    app.register_blueprint(
        create_intelligence_blueprint(
            lambda: None,
            snapshot_getter=snapshot_getter,
            ml_runtime_provider=provider,
        )
    )

    response = app.test_client().get(
        "/api/intelligence?event_limit=25"
    )

    assert response.status_code == 200

    assert observed["provider_calls"] == 1
    assert observed["event_limit"] == "25"
    assert observed["runtime"] is runtime

    payload = response.get_json()

    assert (
        payload["governed_ml_runtime"]["status"]
        == "UNAVAILABLE"
    )


def test_blueprint_without_provider_preserves_old_getter_contract():
    observed = {}

    # Deliberately does NOT accept ml_runtime.
    # Existing injected snapshot getters must remain compatible.
    def legacy_snapshot_getter(
        get_connection,
        *,
        event_limit=None,
    ):
        observed["event_limit"] = event_limit

        return {
            "status": "legacy-compatible",
        }

    app = Flask(__name__)
    app.register_blueprint(
        create_intelligence_blueprint(
            lambda: None,
            snapshot_getter=legacy_snapshot_getter,
        )
    )

    response = app.test_client().get(
        "/api/intelligence?event_limit=10"
    )

    assert response.status_code == 200
    assert observed["event_limit"] == "10"
    assert response.get_json() == {
        "status": "legacy-compatible",
    }


def test_sqlite_snapshot_reader_forwards_runtime(tmp_path):
    db_path = tmp_path / "y11-runtime-api.db"

    conn = sqlite3.connect(db_path)
    try:
        conn.execute(SCHEMA)
        conn.commit()
    finally:
        conn.close()

    def connection_factory():
        connection = sqlite3.connect(db_path)
        connection.row_factory = sqlite3.Row
        return connection

    runtime = unavailable_runtime()

    snapshot = get_intelligence_snapshot(
        connection_factory,
        event_limit=100,
        ml_runtime=runtime,
    )

    assert (
        snapshot["governed_ml_runtime"]["status"]
        == "UNAVAILABLE"
    )
    assert (
        snapshot["governed_ml_runtime"]["model_name"]
        == "aegis-threat-classifier"
    )
    assert snapshot["detection_counts"] == {
        "RULE": 0,
        "ML": 0,
        "CORRELATION": 0,
    }
