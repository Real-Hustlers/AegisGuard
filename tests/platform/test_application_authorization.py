import sqlite3
import tempfile
import unittest
from pathlib import Path

from flask import Flask, jsonify, g

from backend.analyzer.app_authorization import (
    ALL_APPLICATION_ROLES,
    ROLE_ADMINISTRATOR,
    ROLE_ANALYST,
    ROLE_VIEWER,
    install_application_authorization,
    required_roles_for_request,
)
from backend.analyzer.auth_api import (
    AUTH_CSRF_HEADER,
    create_auth_blueprint,
)
from backend.storage.migrations import ensure_platform_schema
from backend.storage.user_auth import create_user


class ApplicationAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "rbac.db"

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

    def make_app(self):
        app = Flask(__name__)
        app.register_blueprint(
            create_auth_blueprint(
                self.connection_factory,
                cookie_secure=False,
                session_ttl_seconds=3600,
            )
        )

        @app.get("/")
        def home():
            return "home"

        @app.get("/api/dashboard")
        def dashboard():
            return jsonify({
                "ok": True,
                "role": g.aegisguard_user["role"],
            })

        @app.get("/api/intelligence")
        def intelligence():
            return jsonify({"ok": True})

        @app.post("/api/incidents/execute")
        def simulate_incident():
            return jsonify({
                "ok": True,
                "role": g.aegisguard_user["role"],
            })

        @app.post("/api/incidents/settings")
        def mutate_settings():
            return jsonify({
                "ok": True,
                "role": g.aegisguard_user["role"],
            })

        @app.post("/api/response-actions/1/approve")
        def approve_action():
            return jsonify({"ok": True})

        @app.post("/api/soar/block-ip")
        def block_ip():
            return jsonify({"ok": True})

        @app.post("/api/incidents/reset")
        def reset_incidents():
            return jsonify({"ok": True})

        @app.post("/api/future-mutation")
        def future_mutation():
            return jsonify({"ok": True})

        @app.post("/api/collector/v1/heartbeat")
        def collector_heartbeat():
            return jsonify({"device": True})

        @app.post("/api/upload_logs")
        def legacy_upload():
            return jsonify({"legacy_device": True})

        install_application_authorization(
            app,
            self.connection_factory,
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

    def test_policy_is_read_all_simulation_analyst_and_mutations_admin(self):
        self.assertEqual(
            required_roles_for_request("/api/dashboard", "GET"),
            ALL_APPLICATION_ROLES,
        )
        self.assertEqual(
            required_roles_for_request(
                "/api/incidents/execute",
                "POST",
            ),
            frozenset({
                ROLE_ADMINISTRATOR,
                ROLE_ANALYST,
            }),
        )
        self.assertEqual(
            required_roles_for_request(
                "/api/incidents/settings",
                "POST",
            ),
            frozenset({ROLE_ADMINISTRATOR}),
        )
        self.assertEqual(
            required_roles_for_request(
                "/api/future-mutation",
                "POST",
            ),
            frozenset({ROLE_ADMINISTRATOR}),
        )

    def test_auth_device_and_home_surfaces_are_outside_human_rbac(self):
        self.assertIsNone(
            required_roles_for_request("/api/auth/login", "POST")
        )
        self.assertIsNone(
            required_roles_for_request(
                "/api/collector/v1/batches",
                "POST",
            )
        )
        self.assertIsNone(
            required_roles_for_request("/api/upload_logs", "POST")
        )
        self.assertIsNone(
            required_roles_for_request("/", "GET")
        )

    def test_unauthenticated_application_api_is_rejected(self):
        client = self.make_app().test_client()

        response = client.get("/api/dashboard")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.get_json()["error"],
            "authentication_required",
        )

    def test_viewer_can_read_but_cannot_mutate(self):
        self.provision("viewer", ROLE_VIEWER)
        client = self.make_app().test_client()
        self.login(client, "viewer")

        read = client.get("/api/dashboard")
        self.assertEqual(read.status_code, 200)
        self.assertEqual(
            read.get_json()["role"],
            ROLE_VIEWER,
        )
        self.assertEqual(
            client.get("/api/intelligence").status_code,
            200,
        )

        self.assertEqual(
            client.post(
                "/api/incidents/execute",
                json={"incident_id": "inc-1"},
            ).status_code,
            403,
        )
        self.assertEqual(
            client.post(
                "/api/incidents/settings",
                json={},
            ).status_code,
            403,
        )

    def test_analyst_can_simulate_but_cannot_change_admin_surfaces(self):
        self.provision("analyst", ROLE_ANALYST)
        client = self.make_app().test_client()
        csrf_token = self.login(client, "analyst")

        simulate = client.post(
            "/api/incidents/execute",
            json={"incident_id": "inc-1"},
            headers={AUTH_CSRF_HEADER: csrf_token},
        )
        self.assertEqual(simulate.status_code, 200)
        self.assertEqual(
            simulate.get_json()["role"],
            ROLE_ANALYST,
        )

        for path in (
            "/api/incidents/settings",
            "/api/response-actions/1/approve",
            "/api/soar/block-ip",
            "/api/incidents/reset",
            "/api/future-mutation",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    client.post(path, json={}).status_code,
                    403,
                )

    def test_administrator_can_reach_state_changing_application_routes(self):
        self.provision("admin", ROLE_ADMINISTRATOR)
        client = self.make_app().test_client()
        csrf_token = self.login(client, "admin")

        for path in (
            "/api/incidents/execute",
            "/api/incidents/settings",
            "/api/response-actions/1/approve",
            "/api/soar/block-ip",
            "/api/incidents/reset",
            "/api/future-mutation",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    client.post(
                        path,
                        json={},
                        headers={AUTH_CSRF_HEADER: csrf_token},
                    ).status_code,
                    200,
                )

    def test_collector_and_legacy_device_ingest_are_not_human_session_gated(self):
        client = self.make_app().test_client()

        self.assertEqual(
            client.post(
                "/api/collector/v1/heartbeat",
                json={},
            ).status_code,
            200,
        )
        self.assertEqual(
            client.post(
                "/api/upload_logs",
                json={},
            ).status_code,
            200,
        )

    def test_authenticated_identity_is_server_derived(self):
        self.provision("viewer", ROLE_VIEWER)
        client = self.make_app().test_client()
        self.login(client, "viewer")

        response = client.get(
            "/api/dashboard",
            headers={
                "X-AegisGuard-Role": "ADMINISTRATOR",
                "X-AegisGuard-User": "forged-admin",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json()["role"],
            ROLE_VIEWER,
        )

    def test_unknown_api_mutation_fails_closed_to_administrator(self):
        self.provision("analyst", ROLE_ANALYST)
        analyst = self.make_app().test_client()
        self.login(analyst, "analyst")
        self.assertEqual(
            analyst.post(
                "/api/future-mutation",
                json={},
            ).status_code,
            403,
        )

        self.provision("admin", ROLE_ADMINISTRATOR)
        admin = self.make_app().test_client()
        csrf_token = self.login(admin, "admin")
        self.assertEqual(
            admin.post(
                "/api/future-mutation",
                json={},
                headers={AUTH_CSRF_HEADER: csrf_token},
            ).status_code,
            200,
        )


if __name__ == "__main__":
    unittest.main()
