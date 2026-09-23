import sys

from backend.analyzer import app as analyzer_app
from backend.analyzer.auth_api import AUTH_SESSION_COOKIE
from backend.storage.user_auth import create_session, create_user


def _authenticate(client):
    conn = analyzer_app.get_connection()
    try:
        user = create_user(
            conn,
            "dashboard-viewer",
            "test-password-dashboard",
            "VIEWER",
            user_id="test-dashboard-viewer",
        )
        session = create_session(
            conn,
            user["user_id"],
            ttl_seconds=3600,
        )
    finally:
        conn.close()

    client.set_cookie(
        AUTH_SESSION_COOKIE,
        session["token"],
    )


def test_dashboard_endpoint_returns_backend_metrics(tmp_path):
    test_db_path = tmp_path / "dashboard.db"
    databases = [
        module
        for module in (
            sys.modules.get("database"),
            sys.modules.get("backend.analyzer.database"),
        )
        if module is not None
    ]
    original_database_state = [
        (database, database.DB_PATH, database._schema_initialized)
        for database in databases
    ]

    try:
        for database in databases:
            database.DB_PATH = test_db_path
            database._schema_initialized = False

        client = analyzer_app.app.test_client()
        _authenticate(client)

        response = client.get("/api/dashboard")

        assert response.status_code == 200

        data = response.get_json()
        assert "events" in data
        assert "threats" in data
        assert "devices" in data
        assert "alerts" in data
        assert isinstance(data["events"], int)
        assert isinstance(data["threats"], int)
        assert isinstance(data["devices"], int)
        assert isinstance(data["alerts"], int)
    finally:
        for database, db_path, schema_state in original_database_state:
            database.DB_PATH = db_path
            database._schema_initialized = schema_state
