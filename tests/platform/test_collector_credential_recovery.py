import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import requests
from flask import Flask

from backend.analyzer.collector_api import (
    RECOVERY_TOKEN_HEADER,
    create_collector_blueprint,
)
from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.state import CollectorState
from backend.storage.collector_identity import (
    CollectorIdentityError,
    CollectorRecoveryConflictError,
    CollectorRevokedError,
    credential_fingerprint,
    enroll_collector,
    recover_collector_credential,
    revoke_collector,
)
from backend.storage.migrations import ensure_platform_schema


class _TestProtector:
    PREFIX = b"TEST-PROTECTED:"

    def protect(self, plaintext: bytes) -> bytes:
        return self.PREFIX + bytes(plaintext)[::-1]

    def unprotect(self, protected: bytes) -> bytes:
        value = bytes(protected)
        if not value.startswith(self.PREFIX):
            raise ValueError("invalid test credential")
        return value[len(self.PREFIX):][::-1]


class CollectorCredentialRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.server_db = root / "server.db"
        self.collector_db = root / "collector-state.db"

        def connection_factory():
            conn = sqlite3.connect(str(self.server_db), timeout=30)
            ensure_platform_schema(conn)
            return conn

        self.connection_factory = connection_factory

    def tearDown(self):
        self.tmp.cleanup()

    def enroll_server(self):
        conn = self.connection_factory()
        try:
            return enroll_collector(
                conn,
                "collector-1",
                "HOST01",
                credential_factory=lambda: "device-secret-001",
            )
        finally:
            conn.close()

    def collector_row(self):
        conn = self.connection_factory()
        try:
            return conn.execute(
                """
                SELECT credential_fingerprint,
                       credential_recovery_id,
                       credential_recovered_at,
                       credential_rotation_id,
                       status,
                       revoked_at
                FROM collectors
                WHERE collector_id='collector-1'
                """
            ).fetchone()
        finally:
            conn.close()

    def make_client(self, recovery_token="recovery-secret"):
        app = Flask(__name__)
        app.register_blueprint(
            create_collector_blueprint(
                self.connection_factory,
                auth_required=True,
                enrollment_token="bootstrap-secret",
                recovery_token=recovery_token,
                credential_factory=lambda: "device-secret-001",
            )
        )
        app.testing = True
        return app.test_client()

    def test_server_recovery_replaces_fingerprint_and_replay_is_idempotent(self):
        self.enroll_server()

        conn = self.connection_factory()
        try:
            first = recover_collector_credential(
                conn,
                "collector-1",
                "HOST01",
                "device-secret-900",
                "recovery-1",
            )
        finally:
            conn.close()

        self.assertFalse(first["duplicate"])
        row = self.collector_row()
        self.assertEqual(
            row[0],
            credential_fingerprint("device-secret-900"),
        )
        self.assertEqual(row[1], "recovery-1")
        self.assertIsNotNone(row[2])

        conn = self.connection_factory()
        try:
            replay = recover_collector_credential(
                conn,
                "collector-1",
                "HOST01",
                "device-secret-900",
                "recovery-1",
            )
        finally:
            conn.close()

        self.assertTrue(replay["duplicate"])

    def test_recovery_id_reuse_with_different_candidate_is_rejected(self):
        self.enroll_server()

        conn = self.connection_factory()
        try:
            recover_collector_credential(
                conn,
                "collector-1",
                "HOST01",
                "device-secret-900",
                "recovery-1",
            )
        finally:
            conn.close()

        conn = self.connection_factory()
        try:
            with self.assertRaises(CollectorRecoveryConflictError):
                recover_collector_credential(
                    conn,
                    "collector-1",
                    "HOST01",
                    "device-secret-901",
                    "recovery-1",
                )
        finally:
            conn.close()

    def test_wrong_hostname_and_revoked_collector_fail_closed(self):
        self.enroll_server()

        conn = self.connection_factory()
        try:
            with self.assertRaises(CollectorIdentityError):
                recover_collector_credential(
                    conn,
                    "collector-1",
                    "OTHER-HOST",
                    "device-secret-900",
                    "recovery-1",
                )
        finally:
            conn.close()

        conn = self.connection_factory()
        try:
            self.assertTrue(revoke_collector(conn, "collector-1"))
        finally:
            conn.close()

        conn = self.connection_factory()
        try:
            with self.assertRaises(CollectorRevokedError):
                recover_collector_credential(
                    conn,
                    "collector-1",
                    "HOST01",
                    "device-secret-900",
                    "recovery-2",
                )
        finally:
            conn.close()

    def test_recovery_api_requires_separate_token_and_never_echoes_secret(self):
        self.enroll_server()

        disabled = self.make_client(recovery_token=None)
        response = disabled.post(
            "/api/collector/v1/recover",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "recovery_id": "recovery-1",
                "new_credential": "device-secret-900",
            },
            headers={RECOVERY_TOKEN_HEADER: "recovery-secret"},
        )
        self.assertEqual(response.status_code, 503)

        client = self.make_client()

        denied = client.post(
            "/api/collector/v1/recover",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "recovery_id": "recovery-1",
                "new_credential": "device-secret-900",
            },
            headers={RECOVERY_TOKEN_HEADER: "wrong-secret"},
        )
        self.assertEqual(denied.status_code, 403)

        recovered = client.post(
            "/api/collector/v1/recover",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "recovery_id": "recovery-1",
                "new_credential": "device-secret-900",
            },
            headers={RECOVERY_TOKEN_HEADER: "recovery-secret"},
        )
        self.assertEqual(recovered.status_code, 200)
        body = recovered.get_json()
        self.assertEqual(body["status"], "recovered")
        self.assertFalse(body["duplicate"])
        self.assertNotIn("credential", body)
        self.assertNotIn("device-secret-900", repr(body))

    def test_pending_recovery_is_protected_and_clears_stale_rotation(self):
        state = CollectorState(
            self.collector_db,
            credential_protector=_TestProtector(),
        )
        state.store_collector_credential("device-secret-001")
        state.begin_credential_rotation(
            "rotation-1",
            "device-secret-002",
        )
        state.begin_credential_recovery(
            "recovery-1",
            "device-secret-900",
        )

        pending = state.get_pending_credential_recovery()
        self.assertEqual(pending["recovery_id"], "recovery-1")
        self.assertEqual(pending["credential"], "device-secret-900")

        state.commit_credential_recovery("recovery-1")

        self.assertEqual(
            state.get_collector_credential(),
            "device-secret-900",
        )
        self.assertIsNone(state.get_pending_credential_recovery())
        self.assertIsNone(state.get_pending_credential_rotation())

        conn = sqlite3.connect(str(self.collector_db))
        try:
            values = [
                str(row[0])
                for row in conn.execute(
                    "SELECT value FROM collector_state"
                ).fetchall()
            ]
        finally:
            conn.close()

        self.assertFalse(
            any("device-secret-900" in value for value in values)
        )

    def test_lost_recovery_response_replays_after_restart(self):
        self.enroll_server()

        state = CollectorState(
            self.collector_db,
            credential_protector=_TestProtector(),
        )
        state.get_or_create_collector_id()
        conn = state._connect()
        try:
            conn.execute(
                """
                UPDATE collector_state
                SET value='collector-1'
                WHERE key='collector_id'
                """
            )
            conn.commit()
        finally:
            conn.close()

        calls = []

        def lost_sender(
            _url,
            payload,
            recovery_token,
            **_kwargs,
        ):
            calls.append(recovery_token)
            conn = self.connection_factory()
            try:
                recover_collector_credential(
                    conn,
                    payload["collector_id"],
                    payload["hostname"],
                    payload["new_credential"],
                    payload["recovery_id"],
                )
            finally:
                conn.close()
            raise requests.RequestException(
                "simulated lost recovery response"
            )

        runtime = DurableCollectorRuntime(
            state,
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            enrollment_url="https://siem.example.test/api/collector/v1/enroll",
            recovery_url="https://siem.example.test/api/collector/v1/recover",
            recovery_token="recovery-secret",
            auth_required=True,
            recovery_sender=lost_sender,
            credential_factory=lambda: "device-secret-900",
            recovery_id_factory=lambda: "recovery-1",
        )
        runtime.collector_id = "collector-1"

        with self.assertRaisesRegex(
            requests.RequestException,
            "lost recovery response",
        ):
            runtime.recover_credential()

        pending = state.get_pending_credential_recovery()
        self.assertEqual(pending["recovery_id"], "recovery-1")
        self.assertEqual(pending["credential"], "device-secret-900")

        replay_calls = []

        def replay_sender(
            _url,
            payload,
            recovery_token,
            **_kwargs,
        ):
            replay_calls.append(recovery_token)
            conn = self.connection_factory()
            try:
                result = recover_collector_credential(
                    conn,
                    payload["collector_id"],
                    payload["hostname"],
                    payload["new_credential"],
                    payload["recovery_id"],
                )
            finally:
                conn.close()

            response = Mock(status_code=200)
            response.json.return_value = {
                "status": "recovered",
                "collector_id": payload["collector_id"],
                "hostname": payload["hostname"],
                "recovery_id": payload["recovery_id"],
                "duplicate": result["duplicate"],
            }
            return response

        restarted_state = CollectorState(
            self.collector_db,
            credential_protector=_TestProtector(),
        )
        restarted = DurableCollectorRuntime(
            restarted_state,
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            enrollment_url="https://siem.example.test/api/collector/v1/enroll",
            recovery_url="https://siem.example.test/api/collector/v1/recover",
            recovery_token="recovery-secret",
            auth_required=True,
            recovery_sender=replay_sender,
        )
        restarted.collector_id = "collector-1"

        result = restarted.recover_credential()

        self.assertTrue(result["duplicate"])
        self.assertEqual(replay_calls, ["recovery-secret"])
        self.assertEqual(
            restarted_state.get_collector_credential(),
            "device-secret-900",
        )
        self.assertIsNone(
            restarted_state.get_pending_credential_recovery()
        )


if __name__ == "__main__":
    unittest.main()
