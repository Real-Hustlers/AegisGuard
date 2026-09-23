import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from flask import Flask, jsonify, g

from backend.analyzer.app_authorization import (
    install_application_authorization,
)
from backend.analyzer.audit_context import (
    AUDIT_CORRELATION_HEADER,
    install_request_correlation,
)
from backend.analyzer.auth_api import (
    AUTH_CSRF_HEADER,
    create_auth_blueprint,
)
from backend.analyzer.sensitive_audit import (
    install_sensitive_operation_auditing,
)
from backend.storage.migrations import ensure_platform_schema
from backend.storage.user_auth import create_user


class SensitiveOperationAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "s52.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection_factory(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA foreign_keys = ON")
        ensure_platform_schema(conn)
        return conn

    def provision(self, username, role):
        conn = self.connection_factory()
        try:
            return create_user(
                conn,
                username,
                "correct-horse-battery",
                role,
                user_id=f"user-{username}",
            )
        finally:
            conn.close()

    def make_app(self):
        app = Flask(__name__)
        app.register_blueprint(
            create_auth_blueprint(
                self.connection_factory,
                cookie_secure=False,
                session_ttl_seconds=3600,
                session_idle_timeout_seconds=1800,
            )
        )

        @app.get("/api/dashboard")
        def dashboard():
            return jsonify({"ok": True})

        @app.post("/api/incidents/settings")
        def settings():
            return jsonify({"updated": True})

        @app.post("/api/incidents/execute")
        def execute():
            payload = g.get("payload_override")
            return jsonify({"success": True})

        @app.post("/api/incidents/reset")
        def reset():
            return jsonify({"success": True})

        @app.post("/api/response-actions/<int:action_id>/approve")
        def approve(action_id):
            return jsonify({"id": action_id, "status": "APPROVED"})

        @app.post("/api/soar/block-ip")
        def block_ip():
            return jsonify({"status": "DRY_RUN"})

        @app.post("/api/soar/unblock-ip")
        def unblock_ip():
            return jsonify({"status": "ROLLED_BACK"})

        @app.post("/api/collector/v1/heartbeat")
        def collector_heartbeat():
            return jsonify({"device": True})

        install_request_correlation(
            app,
            correlation_id_factory=lambda: "req-s52-fixed",
        )
        install_application_authorization(
            app,
            self.connection_factory,
            session_idle_timeout_seconds=1800,
        )
        install_sensitive_operation_auditing(
            app,
            self.connection_factory,
        )
        app.testing = True
        return app

    def audit_rows(self):
        conn = self.connection_factory()
        try:
            return conn.execute(
                """
                SELECT actor_user_id,
                       actor_type,
                       action,
                       target_type,
                       target_id,
                       outcome,
                       correlation_id,
                       details_json
                FROM audit_events
                ORDER BY rowid ASC
                """
            ).fetchall()
        finally:
            conn.close()

    def login(self, client, username, password="correct-horse-battery"):
        response = client.post(
            "/api/auth/login",
            json={
                "username": username,
                "password": password,
            },
        )
        return response

    def test_successful_login_and_logout_are_attributed_to_server_user(self):
        self.provision("admin", "ADMINISTRATOR")
        client = self.make_app().test_client()

        login = self.login(client, "admin")
        self.assertEqual(login.status_code, 200)
        csrf_token = login.get_json()["csrf_token"]

        logout = client.post(
            "/api/auth/logout",
            headers={AUTH_CSRF_HEADER: csrf_token},
        )
        self.assertEqual(logout.status_code, 200)

        rows = self.audit_rows()
        self.assertEqual([row[2] for row in rows], [
            "AUTH.LOGIN",
            "AUTH.LOGOUT",
        ])
        for row in rows:
            self.assertEqual(row[0], "user-admin")
            self.assertEqual(row[1], "USER")
            self.assertEqual(row[5], "SUCCESS")
            self.assertEqual(row[6], "req-s52-fixed")

    def test_failed_login_is_system_denial_and_does_not_store_password(self):
        self.provision("admin", "ADMINISTRATOR")
        client = self.make_app().test_client()

        response = self.login(
            client,
            "admin",
            password="wrong-password-value",
        )
        self.assertEqual(response.status_code, 401)

        row = self.audit_rows()[0]
        self.assertIsNone(row[0])
        self.assertEqual(row[1], "SYSTEM")
        self.assertEqual(row[2], "AUTH.LOGIN")
        self.assertEqual(row[4], "admin")
        self.assertEqual(row[5], "DENIED")

        details_text = row[7]
        self.assertNotIn("wrong-password-value", details_text)
        self.assertNotIn("password", details_text.lower())

    def test_rbac_denial_uses_authenticated_user_not_forged_headers(self):
        self.provision("viewer", "VIEWER")
        client = self.make_app().test_client()
        login = self.login(client, "viewer")
        csrf_token = login.get_json()["csrf_token"]

        response = client.post(
            "/api/incidents/settings",
            json={"soar_mode": "AUTO"},
            headers={
                AUTH_CSRF_HEADER: csrf_token,
                "X-AegisGuard-User": "forged-admin",
                "X-AegisGuard-Role": "ADMINISTRATOR",
            },
        )
        self.assertEqual(response.status_code, 403)

        rows = self.audit_rows()
        denial = rows[-1]
        self.assertEqual(denial[0], "user-viewer")
        self.assertEqual(denial[1], "USER")
        self.assertEqual(denial[2], "AUTHORIZATION.DENIED")
        self.assertEqual(denial[3], "API_PATH")
        self.assertEqual(
            denial[4],
            "/api/incidents/settings",
        )
        self.assertEqual(denial[5], "DENIED")
        self.assertNotIn("forged-admin", denial[7])

    def test_settings_audit_records_keys_not_values_or_csrf(self):
        self.provision("admin", "ADMINISTRATOR")
        client = self.make_app().test_client()
        login = self.login(client, "admin")
        csrf_token = login.get_json()["csrf_token"]

        response = client.post(
            "/api/incidents/settings",
            json={
                "soar_mode": "AUTO",
                "soar_allowlist": ["203.0.113.5"],
            },
            headers={AUTH_CSRF_HEADER: csrf_token},
        )
        self.assertEqual(response.status_code, 200)

        row = self.audit_rows()[-1]
        self.assertEqual(row[2], "SETTINGS.UPDATE")
        details = json.loads(row[7])
        self.assertEqual(
            details["changed_keys"],
            ["soar_allowlist", "soar_mode"],
        )
        self.assertNotIn("203.0.113.5", row[7])
        self.assertNotIn(csrf_token, row[7])

    def test_sensitive_mutations_receive_expected_actions_and_targets(self):
        self.provision("admin", "ADMINISTRATOR")
        client = self.make_app().test_client()
        login = self.login(client, "admin")
        csrf_token = login.get_json()["csrf_token"]
        headers = {AUTH_CSRF_HEADER: csrf_token}

        requests = [
            (
                "/api/response-actions/7/approve",
                {},
                "RESPONSE.APPROVE",
                "7",
            ),
            (
                "/api/soar/block-ip",
                {"ip": "203.0.113.10", "incident_id": "inc-1"},
                "SOAR.BLOCK_IP",
                "203.0.113.10",
            ),
            (
                "/api/soar/unblock-ip",
                {"ip": "203.0.113.10"},
                "SOAR.UNBLOCK_IP",
                "203.0.113.10",
            ),
            (
                "/api/incidents/execute",
                {"incident_id": "inc-1"},
                "INCIDENT.SIMULATE",
                "inc-1",
            ),
            (
                "/api/incidents/reset",
                {},
                "INCIDENT.RESET",
                "all",
            ),
        ]

        for path, payload, action, target in requests:
            with self.subTest(path=path):
                response = client.post(
                    path,
                    json=payload,
                    headers=headers,
                )
                self.assertEqual(response.status_code, 200)
                row = self.audit_rows()[-1]
                self.assertEqual(row[0], "user-admin")
                self.assertEqual(row[2], action)
                self.assertEqual(row[4], target)
                self.assertEqual(row[5], "SUCCESS")

    def test_unauthenticated_read_denial_is_audited_but_read_success_is_not(self):
        app = self.make_app()
        anonymous = app.test_client()

        denied = anonymous.get("/api/dashboard")
        self.assertEqual(denied.status_code, 401)

        self.provision("viewer", "VIEWER")
        viewer = app.test_client()
        self.assertEqual(self.login(viewer, "viewer").status_code, 200)
        self.assertEqual(viewer.get("/api/dashboard").status_code, 200)

        rows = self.audit_rows()
        actions = [row[2] for row in rows]
        self.assertIn("AUTHORIZATION.DENIED", actions)

        # Successful reads are deliberately not audit-noise.
        self.assertEqual(
            actions.count("AUTHORIZATION.DENIED"),
            1,
        )

    def test_collector_boundary_is_not_reclassified_as_human_audit(self):
        client = self.make_app().test_client()

        response = client.post(
            "/api/collector/v1/heartbeat",
            json={},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.audit_rows(), [])


if __name__ == "__main__":
    unittest.main()
