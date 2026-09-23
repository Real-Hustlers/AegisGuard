import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, g, jsonify

from backend.analyzer.audit_context import (
    AUDIT_CORRELATION_HEADER,
    current_request_audit_context,
    install_request_correlation,
)
from backend.platform.contracts import AuditEvent
from backend.storage.audit_log import (
    AuditValidationError,
    record_audit_event,
    sanitize_audit_details,
)
from backend.storage.migrations import (
    LATEST_PLATFORM_SCHEMA_VERSION,
    ensure_platform_schema,
)
from backend.storage.user_auth import create_user


class AuditFoundationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "audit.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA foreign_keys = ON")
        ensure_platform_schema(conn)
        return conn

    def create_user(self):
        conn = self.connection()
        try:
            return create_user(
                conn,
                "audit-admin",
                "correct-horse-battery",
                "ADMINISTRATOR",
                user_id="audit-user-1",
            )
        finally:
            conn.close()

    def test_audit_writer_uses_existing_schema_without_new_migration(self):
        conn = self.connection()
        try:
            self.assertEqual(
                LATEST_PLATFORM_SCHEMA_VERSION,
                9,
            )
            table = conn.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type='table'
                  AND name='audit_events'
                """
            ).fetchone()
        finally:
            conn.close()

        self.assertIsNotNone(table)

    def test_user_audit_event_is_server_identified_and_persisted(self):
        user = self.create_user()
        now = datetime(
            2026,
            9,
            23,
            5,
            45,
            tzinfo=timezone.utc,
        )

        conn = self.connection()
        try:
            event = record_audit_event(
                conn,
                actor_type="USER",
                actor_user_id=user["user_id"],
                action="auth.login",
                outcome="success",
                target_type="session",
                target_id="session-1",
                peer_ip="127.0.0.1",
                correlation_id="req-server-1",
                details={
                    "role": "ADMINISTRATOR",
                    "method": "password",
                },
                now=now,
            )

            row = conn.execute(
                """
                SELECT audit_id,
                       timestamp,
                       actor_user_id,
                       actor_type,
                       action,
                       target_type,
                       target_id,
                       outcome,
                       peer_ip,
                       correlation_id,
                       details_json
                FROM audit_events
                WHERE audit_id = ?
                """,
                (event.audit_id,),
            ).fetchone()
        finally:
            conn.close()

        self.assertIsInstance(event, AuditEvent)
        self.assertTrue(event.audit_id.startswith("audit-"))
        self.assertEqual(
            event.timestamp,
            "2026-09-23T05:45:00Z",
        )
        self.assertEqual(event.action, "AUTH.LOGIN")
        self.assertEqual(event.outcome, "SUCCESS")
        self.assertEqual(row[0], event.audit_id)
        self.assertEqual(row[2], user["user_id"])
        self.assertEqual(row[3], "USER")
        self.assertEqual(row[4], "AUTH.LOGIN")
        self.assertEqual(row[5], "SESSION")
        self.assertEqual(row[7], "SUCCESS")
        self.assertEqual(row[9], "req-server-1")
        self.assertEqual(
            json.loads(row[10])["role"],
            "ADMINISTRATOR",
        )

    def test_callers_cannot_supply_forged_audit_identity(self):
        conn = self.connection()
        try:
            with self.assertRaises(TypeError):
                record_audit_event(
                    conn,
                    actor_type="SYSTEM",
                    action="SYSTEM.START",
                    outcome="SUCCESS",
                    audit_id="forged-audit-id",
                )
        finally:
            conn.close()

    def test_actor_and_outcome_validation_fail_closed(self):
        conn = self.connection()
        try:
            with self.assertRaises(AuditValidationError):
                record_audit_event(
                    conn,
                    actor_type="USER",
                    action="AUTH.LOGIN",
                    outcome="SUCCESS",
                )

            with self.assertRaises(AuditValidationError):
                record_audit_event(
                    conn,
                    actor_type="SYSTEM",
                    actor_user_id="forged-user",
                    action="SYSTEM.START",
                    outcome="SUCCESS",
                )

            with self.assertRaises(AuditValidationError):
                record_audit_event(
                    conn,
                    actor_type="BROWSER",
                    action="AUTH.LOGIN",
                    outcome="SUCCESS",
                )

            with self.assertRaises(AuditValidationError):
                record_audit_event(
                    conn,
                    actor_type="SYSTEM",
                    action="SYSTEM.START",
                    outcome="MAYBE",
                )
        finally:
            conn.close()

    def test_sensitive_details_are_recursively_redacted(self):
        sanitized = sanitize_audit_details({
            "username": "analyst",
            "password": "super-secret-password",
            "nested": {
                "csrf_token": "csrf-value",
                "authorization": "Bearer abc",
                "collector_credential": "device-secret",
                "safe": "retained",
            },
            "list": [
                {
                    "private_key": "-----BEGIN PRIVATE KEY-----abc",
                    "event": "login",
                }
            ],
        })

        self.assertEqual(sanitized["username"], "analyst")
        self.assertEqual(
            sanitized["password"],
            "[REDACTED]",
        )
        self.assertEqual(
            sanitized["nested"]["csrf_token"],
            "[REDACTED]",
        )
        self.assertEqual(
            sanitized["nested"]["authorization"],
            "[REDACTED]",
        )
        self.assertEqual(
            sanitized["nested"]["collector_credential"],
            "[REDACTED]",
        )
        self.assertEqual(
            sanitized["nested"]["safe"],
            "retained",
        )
        self.assertEqual(
            sanitized["list"][0]["private_key"],
            "[REDACTED]",
        )

    def test_request_correlation_is_server_generated_not_client_supplied(self):
        app = Flask(__name__)
        install_request_correlation(
            app,
            correlation_id_factory=lambda: "req-server-fixed",
        )

        @app.get("/context")
        def context():
            return jsonify({
                "g_correlation_id":
                    g.aegisguard_correlation_id,
                "context":
                    current_request_audit_context(),
            })

        app.testing = True
        client = app.test_client()
        response = client.get(
            "/context",
            headers={
                AUDIT_CORRELATION_HEADER:
                    "req-client-forged",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers[AUDIT_CORRELATION_HEADER],
            "req-server-fixed",
        )
        body = response.get_json()
        self.assertEqual(
            body["g_correlation_id"],
            "req-server-fixed",
        )
        self.assertEqual(
            body["context"]["correlation_id"],
            "req-server-fixed",
        )
        self.assertNotEqual(
            body["context"]["correlation_id"],
            "req-client-forged",
        )


if __name__ == "__main__":
    unittest.main()
