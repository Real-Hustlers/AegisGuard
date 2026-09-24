import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.analyzer import app as analyzer_app
from backend.analyzer.auth_api import (
    AUTH_CSRF_HEADER,
    AUTH_SESSION_COOKIE,
)
from backend.storage.user_auth import (
    create_session,
    create_user,
    csrf_token_for_session_token,
)


class SoarApiTests(unittest.TestCase):
    def setUp(self):
        self.path = Path.cwd() / ".aegisguard_soar_api_test.db"
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                candidate.unlink()
        self.databases = [module for module in (
            sys.modules.get("database"), sys.modules.get("backend.analyzer.database")
        ) if module]
        self.original = [(database, database.DB_PATH, database._schema_initialized) for database in self.databases]
        for database in self.databases:
            database.DB_PATH = self.path
            database._schema_initialized = False
        self.client = analyzer_app.app.test_client()

        conn = analyzer_app.get_connection()
        try:
            user = create_user(
                conn,
                "soar-admin",
                "test-password-soar-admin",
                "ADMINISTRATOR",
                user_id="test-soar-admin",
            )
            session = create_session(
                conn,
                user["user_id"],
                ttl_seconds=3600,
            )
        finally:
            conn.close()

        self.client.set_cookie(
            AUTH_SESSION_COOKIE,
            session["token"],
        )
        self.csrf_token = csrf_token_for_session_token(
            session["token"]
        )

    def tearDown(self):
        for database, path, initialized in self.original:
            database.DB_PATH = path
            database._schema_initialized = initialized
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                candidate.unlink()

    def test_recent_actions_api_and_manual_dry_run_block(self):
        settings = self.client.get("/api/incidents/settings").get_json()
        self.assertEqual(settings["soar_mode"], "MANUAL")
        self.assertTrue(settings["soar_dry_run"])

        requested = self.client.post(
            "/api/soar/block-ip",
            json={"ip": "8.8.8.8", "reason": "controlled demo"},
            headers={AUTH_CSRF_HEADER: self.csrf_token},
        )
        self.assertEqual(requested.status_code, 200)
        action = requested.get_json()
        self.assertEqual(action["status"], "PENDING_APPROVAL")
        self.assertEqual(action["requested_by_user_id"], "test-soar-admin")
        self.assertIsNone(action["approved_by_user_id"])
        self.assertEqual(action["approval_required"], 1)

        approved = self.client.post(
            f"/api/response-actions/{action['id']}/approve",
            json={},
            headers={AUTH_CSRF_HEADER: self.csrf_token},
        )
        self.assertEqual(approved.status_code, 200)
        approved_action = approved.get_json()
        self.assertEqual(approved_action["status"], "DRY_RUN")
        self.assertEqual(
            approved_action["approved_by_user_id"],
            "test-soar-admin",
        )
        self.assertIn(
            "AegisGuard-owned inbound Windows Firewall rule",
            approved_action["simulation_result"],
        )

        recent = self.client.get("/api/response-actions")
        self.assertEqual(recent.status_code, 200)
        self.assertEqual(len(recent.get_json()), 1)
        self.assertEqual(recent.get_json()[0]["target"], "8.8.8.8")

    def test_unblock_uses_trusted_authenticated_actor(self):
        with patch.object(
            analyzer_app.SoarEngine,
            "unblock",
            return_value={
                "status": "SKIPPED",
                "target": "8.8.8.8",
            },
        ) as unblock:
            response = self.client.post(
                "/api/soar/unblock-ip",
                json={
                    "ip": "8.8.8.8",
                    "rollback_by_user_id": "forged-client-user",
                },
                headers={AUTH_CSRF_HEADER: self.csrf_token},
            )

        self.assertEqual(response.status_code, 200)
        unblock.assert_called_once_with(
            "8.8.8.8",
            "operator requested rollback",
            rollback_by_user_id="test-soar-admin",
        )


if __name__ == "__main__":
    unittest.main()
