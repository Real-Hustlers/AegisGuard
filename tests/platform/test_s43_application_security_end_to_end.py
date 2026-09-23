import sqlite3
import tempfile
import unittest
from pathlib import Path

from flask import Flask, jsonify

from backend.analyzer.app_authorization import (
    install_application_authorization,
)
from backend.analyzer.auth_api import (
    AUTH_CSRF_HEADER,
    create_auth_blueprint,
)
from backend.analyzer.browser_security import (
    install_browser_security_headers,
)
from backend.storage.migrations import ensure_platform_schema
from backend.storage.user_auth import create_user


class S43ApplicationSecurityEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "s43.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection_factory(self):
        conn = sqlite3.connect(str(self.db_path))
        ensure_platform_schema(conn)
        return conn

    def provision(self, username, role):
        conn = self.connection_factory()
        try:
            create_user(
                conn,
                username,
                "correct-horse-battery",
                role,
                user_id=f"user-{username}",
            )
        finally:
            conn.close()

    def make_app(self, *, idle_timeout=1800):
        app = Flask(__name__)
        app.register_blueprint(
            create_auth_blueprint(
                self.connection_factory,
                cookie_secure=False,
                session_ttl_seconds=3600,
                session_idle_timeout_seconds=idle_timeout,
                login_failure_limit=5,
                login_window_seconds=300,
                login_block_seconds=300,
            )
        )

        @app.get("/")
        def home():
            return "home"

        @app.get("/api/dashboard")
        def dashboard():
            return jsonify({"ok": True})

        @app.post("/api/incidents/settings")
        def settings():
            return jsonify({"changed": True})

        @app.post("/api/incidents/execute")
        def simulate():
            return jsonify({"simulated": True})

        @app.post("/api/collector/v1/heartbeat")
        def collector_heartbeat():
            return jsonify({"device": True})

        install_application_authorization(
            app,
            self.connection_factory,
            session_idle_timeout_seconds=idle_timeout,
        )
        install_browser_security_headers(app)
        app.testing = True
        return app

    def login(self, client, username, password="correct-horse-battery"):
        return client.post(
            "/api/auth/login",
            json={
                "username": username,
                "password": password,
            },
        )

    def test_csrf_role_session_and_logout_lifecycle(self):
        self.provision("viewer", "VIEWER")
        self.provision("admin", "ADMINISTRATOR")
        app = self.make_app()

        viewer = app.test_client()
        viewer_login = self.login(viewer, "viewer")
        self.assertEqual(viewer_login.status_code, 200)
        viewer_csrf = viewer_login.get_json()["csrf_token"]
        self.assertTrue(viewer_csrf)

        read = viewer.get("/api/dashboard")
        self.assertEqual(read.status_code, 200)

        denied_by_role = viewer.post(
            "/api/incidents/settings",
            json={},
            headers={AUTH_CSRF_HEADER: viewer_csrf},
        )
        self.assertEqual(denied_by_role.status_code, 403)
        self.assertEqual(
            denied_by_role.get_json()["error"],
            "forbidden",
        )

        admin = app.test_client()
        admin_login = self.login(admin, "admin")
        self.assertEqual(admin_login.status_code, 200)
        admin_csrf = admin_login.get_json()["csrf_token"]

        no_csrf = admin.post(
            "/api/incidents/settings",
            json={},
        )
        self.assertEqual(no_csrf.status_code, 403)
        self.assertEqual(
            no_csrf.get_json()["error"],
            "csrf_required",
        )

        wrong_csrf = admin.post(
            "/api/incidents/settings",
            json={},
            headers={AUTH_CSRF_HEADER: viewer_csrf},
        )
        self.assertEqual(wrong_csrf.status_code, 403)
        self.assertEqual(
            wrong_csrf.get_json()["error"],
            "csrf_required",
        )

        changed = admin.post(
            "/api/incidents/settings",
            json={},
            headers={AUTH_CSRF_HEADER: admin_csrf},
        )
        self.assertEqual(changed.status_code, 200)

        logout_without_csrf = admin.post("/api/auth/logout")
        self.assertEqual(logout_without_csrf.status_code, 403)

        logout = admin.post(
            "/api/auth/logout",
            headers={AUTH_CSRF_HEADER: admin_csrf},
        )
        self.assertEqual(logout.status_code, 200)
        self.assertEqual(
            admin.get("/api/auth/me").status_code,
            401,
        )

    def test_idle_timeout_invalidates_persistent_session(self):
        self.provision("admin", "ADMINISTRATOR")
        app = self.make_app(idle_timeout=60)
        client = app.test_client()

        login = self.login(client, "admin")
        self.assertEqual(login.status_code, 200)

        conn = self.connection_factory()
        try:
            conn.execute(
                """
                UPDATE sessions
                SET last_seen_at = '2000-01-01T00:00:00Z'
                """
            )
            conn.commit()
        finally:
            conn.close()

        self.assertEqual(
            client.get("/api/auth/me").status_code,
            401,
        )
        self.assertEqual(
            client.get("/api/dashboard").status_code,
            401,
        )

    def test_login_throttle_is_persistent_and_success_clears_bucket(self):
        self.provision("admin", "ADMINISTRATOR")
        app = self.make_app()
        client = app.test_client()

        for attempt in range(1, 5):
            response = self.login(
                client,
                "admin",
                password="wrong-password-value",
            )
            self.assertEqual(
                response.status_code,
                401,
                msg=f"attempt={attempt}",
            )

        blocked = self.login(
            client,
            "admin",
            password="wrong-password-value",
        )
        self.assertEqual(blocked.status_code, 429)

        restarted = app.test_client()
        still_blocked = self.login(
            restarted,
            "admin",
            password="correct-horse-battery",
        )
        self.assertEqual(still_blocked.status_code, 429)

        conn = self.connection_factory()
        try:
            conn.execute("DELETE FROM auth_login_throttle")
            conn.commit()
        finally:
            conn.close()

        self.assertEqual(
            self.login(
                restarted,
                "admin",
                password="wrong-password-value",
            ).status_code,
            401,
        )
        success = self.login(restarted, "admin")
        self.assertEqual(success.status_code, 200)

        conn = self.connection_factory()
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM auth_login_throttle"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 0)

    def test_browser_headers_and_device_boundary_remain_intact(self):
        app = self.make_app()
        client = app.test_client()

        home = client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertEqual(
            home.headers["X-Content-Type-Options"],
            "nosniff",
        )
        self.assertEqual(
            home.headers["X-Frame-Options"],
            "DENY",
        )
        self.assertEqual(
            home.headers["Referrer-Policy"],
            "no-referrer",
        )
        self.assertIn(
            "frame-ancestors 'none'",
            home.headers["Content-Security-Policy"],
        )

        collector = client.post(
            "/api/collector/v1/heartbeat",
            json={},
        )
        self.assertEqual(collector.status_code, 200)


if __name__ == "__main__":
    unittest.main()
