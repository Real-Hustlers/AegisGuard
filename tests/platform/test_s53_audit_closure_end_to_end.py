import sqlite3
import tempfile
import unittest
from pathlib import Path

from flask import Flask, jsonify

from backend.analyzer.app_authorization import (
    ROLE_ADMINISTRATOR,
    ROLE_VIEWER,
    install_application_authorization,
)
from backend.analyzer.audit_api import create_audit_blueprint
from backend.analyzer.audit_context import install_request_correlation
from backend.analyzer.auth_api import (
    AUTH_CSRF_HEADER,
    create_auth_blueprint,
)
from backend.analyzer.sensitive_audit import (
    install_sensitive_operation_auditing,
)
from backend.storage.audit_integrity import verify_audit_chain
from backend.storage.migrations import (
    LATEST_PLATFORM_SCHEMA_VERSION,
    ensure_platform_schema,
)
from backend.storage.user_auth import create_user


class S53AuditClosureEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "s53.db"

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
        app.register_blueprint(
            create_audit_blueprint(
                self.connection_factory,
                retention_days=365,
            )
        )

        @app.get("/api/dashboard")
        def dashboard():
            return jsonify({"ok": True})

        @app.post("/api/incidents/settings")
        def settings():
            return jsonify({"updated": True})

        install_request_correlation(
            app,
            correlation_id_factory=lambda: "req-s53-fixed",
        )
        install_application_authorization(
            app,
            self.connection_factory,
            session_idle_timeout_seconds=1800,
        )
        install_sensitive_operation_auditing(
            app,
            self.connection_factory,
            retention_days=365,
        )
        app.testing = True
        return app

    def login(self, client, username):
        response = client.post(
            "/api/auth/login",
            json={
                "username": username,
                "password": "correct-horse-battery",
            },
        )
        self.assertEqual(response.status_code, 200)
        return response.get_json()["csrf_token"]

    def test_schema_v9_adds_audit_chain_and_retention_columns(self):
        conn = self.connection_factory()
        try:
            self.assertEqual(LATEST_PLATFORM_SCHEMA_VERSION, 9)
            columns = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(audit_events)"
                ).fetchall()
            }
        finally:
            conn.close()

        self.assertTrue({
            "chain_sequence",
            "previous_hash",
            "event_hash",
            "retention_until",
        }.issubset(columns))

    def test_viewer_cannot_read_audit_evidence_but_admin_can(self):
        self.provision("viewer", ROLE_VIEWER)
        self.provision("admin", ROLE_ADMINISTRATOR)
        app = self.make_app()

        viewer = app.test_client()
        self.login(viewer, "viewer")
        denied = viewer.get("/api/audit/events")
        self.assertEqual(denied.status_code, 403)

        admin = app.test_client()
        admin_csrf = self.login(admin, "admin")
        self.assertTrue(admin_csrf)

        changed = admin.post(
            "/api/incidents/settings",
            json={"soar_mode": "MANUAL"},
            headers={AUTH_CSRF_HEADER: admin_csrf},
        )
        self.assertEqual(changed.status_code, 200)

        evidence = admin.get(
            "/api/audit/events?action=SETTINGS.UPDATE&limit=20"
        )
        self.assertEqual(evidence.status_code, 200)
        body = evidence.get_json()
        self.assertGreaterEqual(body["count"], 1)
        self.assertTrue(
            all(
                event["action"] == "SETTINGS.UPDATE"
                for event in body["events"]
            )
        )

    def test_integrity_is_valid_and_retention_blocks_early_delete(self):
        self.provision("admin", ROLE_ADMINISTRATOR)
        app = self.make_app()
        admin = app.test_client()
        csrf = self.login(admin, "admin")

        self.assertEqual(
            admin.post(
                "/api/incidents/settings",
                json={"soar_mode": "MANUAL"},
                headers={AUTH_CSRF_HEADER: csrf},
            ).status_code,
            200,
        )

        integrity = admin.get("/api/audit/integrity")
        self.assertEqual(integrity.status_code, 200)
        result = integrity.get_json()
        self.assertTrue(result["valid"])
        self.assertEqual(result["retention_days"], 365)
        self.assertGreaterEqual(result["event_count"], 2)

        conn = self.connection_factory()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    DELETE FROM audit_events
                    WHERE chain_sequence = 1
                    """
                )
                conn.commit()
        finally:
            conn.close()

    def test_direct_tampering_is_detected(self):
        self.provision("admin", ROLE_ADMINISTRATOR)
        app = self.make_app()
        admin = app.test_client()
        csrf = self.login(admin, "admin")

        self.assertEqual(
            admin.post(
                "/api/incidents/settings",
                json={"soar_mode": "AUTO"},
                headers={AUTH_CSRF_HEADER: csrf},
            ).status_code,
            200,
        )

        conn = self.connection_factory()
        try:
            before = verify_audit_chain(conn)
            self.assertTrue(before["valid"])

            conn.execute(
                """
                UPDATE audit_events
                SET outcome = 'FAILURE'
                WHERE action = 'SETTINGS.UPDATE'
                """
            )
            conn.commit()

            after = verify_audit_chain(conn)
        finally:
            conn.close()

        self.assertFalse(after["valid"])
        self.assertEqual(
            after["reason"],
            "event_hash_mismatch",
        )

    def test_audit_reads_and_integrity_checks_are_themselves_audited(self):
        self.provision("admin", ROLE_ADMINISTRATOR)
        app = self.make_app()
        admin = app.test_client()
        self.login(admin, "admin")

        self.assertEqual(
            admin.get("/api/audit/events").status_code,
            200,
        )
        self.assertEqual(
            admin.get("/api/audit/integrity").status_code,
            200,
        )

        conn = self.connection_factory()
        try:
            actions = [
                row[0]
                for row in conn.execute(
                    """
                    SELECT action
                    FROM audit_events
                    ORDER BY chain_sequence ASC
                    """
                ).fetchall()
            ]
            result = verify_audit_chain(conn)
        finally:
            conn.close()

        self.assertIn("AUDIT.READ", actions)
        self.assertIn("AUDIT.VERIFY", actions)
        self.assertTrue(result["valid"])


if __name__ == "__main__":
    unittest.main()
