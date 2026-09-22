import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import requests
from flask import Flask

from backend.analyzer.collector_api import (
    COLLECTOR_CREDENTIAL_HEADER,
    ENROLLMENT_TOKEN_HEADER,
    create_collector_blueprint,
)
from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.state import CollectorState
from backend.storage.collector_identity import (
    CollectorAuthenticationError,
    CollectorRevokedError,
    CollectorRotationConflictError,
    credential_fingerprint,
    enroll_collector,
    revoke_collector,
    rotate_collector_credential,
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


class CollectorCredentialRotationTests(unittest.TestCase):
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
                       credential_rotation_id,
                       credential_rotated_at,
                       status
                FROM collectors
                WHERE collector_id='collector-1'
                """
            ).fetchone()
        finally:
            conn.close()

    def make_api_client(self):
        app = Flask(__name__)
        app.register_blueprint(
            create_collector_blueprint(
                self.connection_factory,
                auth_required=True,
                enrollment_token="bootstrap-secret",
                credential_factory=lambda: "device-secret-001",
            )
        )
        app.testing = True
        return app.test_client()

    def test_server_rotation_changes_fingerprint_and_replay_is_idempotent(self):
        self.enroll_server()

        conn = self.connection_factory()
        try:
            first = rotate_collector_credential(
                conn,
                "collector-1",
                "device-secret-001",
                "device-secret-002",
                "rotation-1",
                hostname="HOST01",
            )
        finally:
            conn.close()

        self.assertFalse(first["duplicate"])
        row = self.collector_row()
        self.assertEqual(
            row[0],
            credential_fingerprint("device-secret-002"),
        )
        self.assertEqual(row[1], "rotation-1")
        self.assertIsNotNone(row[2])

        conn = self.connection_factory()
        try:
            replay = rotate_collector_credential(
                conn,
                "collector-1",
                "device-secret-002",
                "device-secret-002",
                "rotation-1",
                hostname="HOST01",
            )
        finally:
            conn.close()

        self.assertTrue(replay["duplicate"])

        conn = self.connection_factory()
        try:
            with self.assertRaises(CollectorAuthenticationError):
                rotate_collector_credential(
                    conn,
                    "collector-1",
                    "device-secret-001",
                    "device-secret-002",
                    "rotation-1",
                    hostname="HOST01",
                )
        finally:
            conn.close()

    def test_rotation_id_reuse_with_different_candidate_is_rejected(self):
        self.enroll_server()

        conn = self.connection_factory()
        try:
            rotate_collector_credential(
                conn,
                "collector-1",
                "device-secret-001",
                "device-secret-002",
                "rotation-1",
                hostname="HOST01",
            )
        finally:
            conn.close()

        conn = self.connection_factory()
        try:
            with self.assertRaises(CollectorRotationConflictError):
                rotate_collector_credential(
                    conn,
                    "collector-1",
                    "device-secret-002",
                    "device-secret-003",
                    "rotation-1",
                    hostname="HOST01",
                )
        finally:
            conn.close()

    def test_revoked_collector_cannot_rotate(self):
        self.enroll_server()
        conn = self.connection_factory()
        try:
            self.assertTrue(revoke_collector(conn, "collector-1"))
        finally:
            conn.close()

        conn = self.connection_factory()
        try:
            with self.assertRaises(CollectorRevokedError):
                rotate_collector_credential(
                    conn,
                    "collector-1",
                    "device-secret-001",
                    "device-secret-002",
                    "rotation-1",
                    hostname="HOST01",
                )
        finally:
            conn.close()

    def test_rotation_api_never_echoes_new_credential(self):
        client = self.make_api_client()

        enrolled = client.post(
            "/api/collector/v1/enroll",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
            },
            headers={
                ENROLLMENT_TOKEN_HEADER: "bootstrap-secret",
            },
        )
        self.assertEqual(enrolled.status_code, 201)

        response = client.post(
            "/api/collector/v1/rotate",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "rotation_id": "rotation-1",
                "new_credential": "device-secret-002",
            },
            headers={
                "X-AegisGuard-Collector-ID": "collector-1",
                COLLECTOR_CREDENTIAL_HEADER: "device-secret-001",
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["status"], "rotated")
        self.assertFalse(body["duplicate"])
        self.assertEqual(body["rotation_id"], "rotation-1")
        self.assertNotIn("credential", body)
        self.assertNotIn("device-secret-002", repr(body))

    def test_pending_rotation_is_protected_and_promoted_atomically(self):
        state = CollectorState(
            self.collector_db,
            credential_protector=_TestProtector(),
        )
        state.store_collector_credential("device-secret-001")

        state.begin_credential_rotation(
            "rotation-1",
            "device-secret-002",
        )

        pending = state.get_pending_credential_rotation()
        self.assertEqual(pending["rotation_id"], "rotation-1")
        self.assertEqual(pending["credential"], "device-secret-002")
        self.assertEqual(
            state.get_collector_credential(),
            "device-secret-001",
        )

        state.commit_credential_rotation("rotation-1")

        self.assertIsNone(state.get_pending_credential_rotation())
        self.assertEqual(
            state.get_collector_credential(),
            "device-secret-002",
        )

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
            any("device-secret-001" in value for value in values)
        )
        self.assertFalse(
            any("device-secret-002" in value for value in values)
        )

    def _seed_runtime_state(self):
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
        state.store_collector_credential("device-secret-001")
        return state

    def test_runtime_successful_rotation_promotes_candidate(self):
        self.enroll_server()
        state = self._seed_runtime_state()
        calls = []

        def rotation_sender(_url, payload, *, credential=None, **_kwargs):
            calls.append(credential)
            conn = self.connection_factory()
            try:
                result = rotate_collector_credential(
                    conn,
                    payload["collector_id"],
                    credential,
                    payload["new_credential"],
                    payload["rotation_id"],
                    hostname=payload["hostname"],
                )
            finally:
                conn.close()

            response = Mock(status_code=200)
            response.json.return_value = {
                "status": "rotated",
                "collector_id": payload["collector_id"],
                "hostname": payload["hostname"],
                "rotation_id": payload["rotation_id"],
                "duplicate": result["duplicate"],
            }
            return response

        runtime = DurableCollectorRuntime(
            state,
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            enrollment_url="https://siem.example.test/api/collector/v1/enroll",
            rotation_url="https://siem.example.test/api/collector/v1/rotate",
            auth_required=True,
            rotation_sender=rotation_sender,
            credential_factory=lambda: "device-secret-002",
            rotation_id_factory=lambda: "rotation-1",
        )
        runtime.collector_id = "collector-1"

        result = runtime.rotate_credential()

        self.assertFalse(result["duplicate"])
        self.assertEqual(calls, ["device-secret-001"])
        self.assertEqual(
            state.get_collector_credential(),
            "device-secret-002",
        )
        self.assertIsNone(state.get_pending_credential_rotation())

    def test_lost_rotation_response_recovers_after_restart_without_lockout(self):
        self.enroll_server()
        state = self._seed_runtime_state()

        first_calls = []

        def lost_response_sender(_url, payload, *, credential=None, **_kwargs):
            first_calls.append(credential)
            conn = self.connection_factory()
            try:
                rotate_collector_credential(
                    conn,
                    payload["collector_id"],
                    credential,
                    payload["new_credential"],
                    payload["rotation_id"],
                    hostname=payload["hostname"],
                )
            finally:
                conn.close()
            raise requests.RequestException(
                "simulated lost rotation response"
            )

        runtime = DurableCollectorRuntime(
            state,
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            enrollment_url="https://siem.example.test/api/collector/v1/enroll",
            rotation_url="https://siem.example.test/api/collector/v1/rotate",
            auth_required=True,
            rotation_sender=lost_response_sender,
            credential_factory=lambda: "device-secret-002",
            rotation_id_factory=lambda: "rotation-1",
        )
        runtime.collector_id = "collector-1"

        with self.assertRaisesRegex(
            requests.RequestException,
            "lost rotation response",
        ):
            runtime.rotate_credential()

        self.assertEqual(first_calls, ["device-secret-001"])
        self.assertEqual(
            state.get_collector_credential(),
            "device-secret-001",
        )
        pending = state.get_pending_credential_rotation()
        self.assertEqual(pending["rotation_id"], "rotation-1")
        self.assertEqual(pending["credential"], "device-secret-002")

        replay_calls = []

        def replay_sender(_url, payload, *, credential=None, **_kwargs):
            replay_calls.append(credential)
            conn = self.connection_factory()
            try:
                try:
                    result = rotate_collector_credential(
                        conn,
                        payload["collector_id"],
                        credential,
                        payload["new_credential"],
                        payload["rotation_id"],
                        hostname=payload["hostname"],
                    )
                except CollectorAuthenticationError:
                    response = Mock(status_code=401)
                    response.json.return_value = {
                        "status": "error",
                        "message": "collector authentication failed",
                    }
                    return response
            finally:
                conn.close()

            response = Mock(status_code=200)
            response.json.return_value = {
                "status": "rotated",
                "collector_id": payload["collector_id"],
                "hostname": payload["hostname"],
                "rotation_id": payload["rotation_id"],
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
            rotation_url="https://siem.example.test/api/collector/v1/rotate",
            auth_required=True,
            rotation_sender=replay_sender,
        )
        restarted.collector_id = "collector-1"

        result = restarted.rotate_credential()

        self.assertTrue(result["duplicate"])
        self.assertEqual(
            replay_calls,
            ["device-secret-001", "device-secret-002"],
        )
        self.assertEqual(
            restarted_state.get_collector_credential(),
            "device-secret-002",
        )
        self.assertIsNone(
            restarted_state.get_pending_credential_rotation()
        )


if __name__ == "__main__":
    unittest.main()
