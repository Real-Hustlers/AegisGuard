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
        self.approver_client = analyzer_app.app.test_client()

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
            approver_user = create_user(
                conn,
                "soar-approver",
                "test-password-soar-approver",
                "ADMINISTRATOR",
                user_id="test-soar-approver",
            )
            approver_session = create_session(
                conn,
                approver_user["user_id"],
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
        self.approver_client.set_cookie(
            AUTH_SESSION_COOKIE,
            approver_session["token"],
        )
        self.approver_csrf_token = (
            csrf_token_for_session_token(
                approver_session["token"]
            )
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

        self_approval = self.client.post(
            f"/api/response-actions/{action['id']}/approve",
            json={},
            headers={AUTH_CSRF_HEADER: self.csrf_token},
        )
        self.assertEqual(self_approval.status_code, 403)
        self.assertEqual(
            self_approval.get_json()["error"],
            "self_approval_forbidden",
        )

        unchanged = self.client.get(
            f"/api/response-actions/{action['id']}"
        )
        self.assertEqual(unchanged.status_code, 200)
        self.assertEqual(
            unchanged.get_json()["status"],
            "PENDING_APPROVAL",
        )
        self.assertIsNone(
            unchanged.get_json()["approved_by_user_id"]
        )

        conn = analyzer_app.get_connection()
        try:
            denial = conn.execute(
                """
                SELECT actor_user_id,
                       outcome,
                       details_json
                FROM audit_events
                WHERE action='RESPONSE.APPROVE'
                ORDER BY rowid DESC
                LIMIT 1
                """
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(denial)
        self.assertEqual(denial["actor_user_id"], "test-soar-admin")
        self.assertEqual(denial["outcome"], "DENIED")
        self.assertIn(
            "self_approval_forbidden",
            denial["details_json"],
        )

        approved = self.approver_client.post(
            f"/api/response-actions/{action['id']}/approve",
            json={},
            headers={
                AUTH_CSRF_HEADER: self.approver_csrf_token,
            },
        )
        self.assertEqual(approved.status_code, 200)
        approved_action = approved.get_json()
        self.assertEqual(approved_action["status"], "DRY_RUN")
        self.assertEqual(
            approved_action["approved_by_user_id"],
            "test-soar-approver",
        )
        self.assertIn(
            "AegisGuard-owned inbound Windows Firewall rule",
            approved_action["simulation_result"],
        )

        recent = self.client.get("/api/response-actions")
        self.assertEqual(recent.status_code, 200)
        self.assertEqual(len(recent.get_json()), 1)
        self.assertEqual(recent.get_json()[0]["target"], "8.8.8.8")

    def test_reconcile_uses_trusted_authenticated_actor_and_is_audited(self):
        with patch.object(
            analyzer_app.SoarEngine,
            "reconcile",
            return_value={
                "id": 321,
                "status": "EXECUTED",
                "rollback_status": None,
            },
        ) as reconcile:
            response = self.approver_client.post(
                "/api/response-actions/321/reconcile",
                json={
                    "reconciled_by_user_id": "forged-client-user",
                },
                headers={
                    AUTH_CSRF_HEADER: self.approver_csrf_token,
                },
            )

        self.assertEqual(response.status_code, 200)
        reconcile.assert_called_once_with(
            321,
            reconciled_by_user_id="test-soar-approver",
        )

        conn = analyzer_app.get_connection()
        try:
            audit = conn.execute(
                """
                SELECT actor_user_id,
                       action,
                       outcome,
                       target_id
                FROM audit_events
                WHERE action='RESPONSE.RECONCILE'
                ORDER BY rowid DESC
                LIMIT 1
                """
            ).fetchone()
        finally:
            conn.close()

        self.assertIsNotNone(audit)
        self.assertEqual(
            audit["actor_user_id"],
            "test-soar-approver",
        )
        self.assertEqual(audit["action"], "RESPONSE.RECONCILE")
        self.assertEqual(audit["outcome"], "SUCCESS")
        self.assertEqual(audit["target_id"], "321")

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
