import sqlite3
import tempfile
import unittest
from pathlib import Path

from flask import Flask

from backend.analyzer.collector_api import (
    COLLECTOR_CREDENTIAL_HEADER,
    ENROLLMENT_TOKEN_HEADER,
    RECOVERY_TOKEN_HEADER,
    create_collector_blueprint,
)
from backend.collector.state import CollectorState
from backend.storage.collector_identity import (
    credential_fingerprint,
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


class S32CredentialSecurityEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.server_db = root / "server.db"
        self.collector_db = root / "collector.db"

        def connection_factory():
            conn = sqlite3.connect(str(self.server_db), timeout=30)
            ensure_platform_schema(conn)
            return conn

        self.connection_factory = connection_factory

        app = Flask(__name__)
        app.register_blueprint(
            create_collector_blueprint(
                self.connection_factory,
                auth_required=True,
                enrollment_token="bootstrap-secret",
                recovery_token="recovery-secret",
                credential_factory=lambda: "device-secret-001",
            )
        )
        app.testing = True
        self.client = app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_enroll_rotate_recover_and_revocation_boundary(self):
        collector_id = "collector-1"
        hostname = "HOST01"

        enrolled = self.client.post(
            "/api/collector/v1/enroll",
            json={
                "collector_id": collector_id,
                "hostname": hostname,
            },
            headers={
                ENROLLMENT_TOKEN_HEADER: "bootstrap-secret",
            },
        )
        self.assertEqual(enrolled.status_code, 201)
        self.assertEqual(
            enrolled.get_json()["credential"],
            "device-secret-001",
        )

        state = CollectorState(
            self.collector_db,
            credential_protector=_TestProtector(),
        )
        state.store_collector_credential("device-secret-001")

        state.begin_credential_rotation(
            "rotation-1",
            "device-secret-002",
        )
        rotated = self.client.post(
            "/api/collector/v1/rotate",
            json={
                "collector_id": collector_id,
                "hostname": hostname,
                "rotation_id": "rotation-1",
                "new_credential": "device-secret-002",
            },
            headers={
                "X-AegisGuard-Collector-ID": collector_id,
                COLLECTOR_CREDENTIAL_HEADER: "device-secret-001",
            },
        )
        self.assertEqual(rotated.status_code, 200)
        state.commit_credential_rotation("rotation-1")
        self.assertEqual(
            state.get_collector_credential(),
            "device-secret-002",
        )

        # Emergency recovery replaces a lost/unusable current credential
        # through the separate recovery trust path.
        state.begin_credential_recovery(
            "recovery-1",
            "device-secret-900",
        )
        recovered = self.client.post(
            "/api/collector/v1/recover",
            json={
                "collector_id": collector_id,
                "hostname": hostname,
                "recovery_id": "recovery-1",
                "new_credential": "device-secret-900",
            },
            headers={
                RECOVERY_TOKEN_HEADER: "recovery-secret",
            },
        )
        self.assertEqual(recovered.status_code, 200)
        state.commit_credential_recovery("recovery-1")
        self.assertEqual(
            state.get_collector_credential(),
            "device-secret-900",
        )

        payload = {
            "batch_id": "batch-after-recovery",
            "collector_id": collector_id,
            "hostname": hostname,
            "os": "Windows",
            "logs": [{"record_id": 500}],
        }
        accepted = self.client.post(
            "/api/collector/v1/batches",
            json=payload,
            headers={
                "X-AegisGuard-Collector-ID": collector_id,
                "X-AegisGuard-Batch-ID": "batch-after-recovery",
                COLLECTOR_CREDENTIAL_HEADER: "device-secret-900",
            },
        )
        self.assertEqual(accepted.status_code, 202)

        conn = self.connection_factory()
        try:
            row = conn.execute(
                """
                SELECT credential_fingerprint,
                       credential_recovery_id,
                       credential_rotation_id
                FROM collectors
                WHERE collector_id=?
                """,
                (collector_id,),
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(
            row[0],
            credential_fingerprint("device-secret-900"),
        )
        self.assertEqual(row[1], "recovery-1")
        self.assertIsNone(row[2])

        conn = self.connection_factory()
        try:
            self.assertTrue(revoke_collector(conn, collector_id))
        finally:
            conn.close()

        denied_batch = self.client.post(
            "/api/collector/v1/batches",
            json={
                **payload,
                "batch_id": "batch-after-revoke",
            },
            headers={
                "X-AegisGuard-Collector-ID": collector_id,
                "X-AegisGuard-Batch-ID": "batch-after-revoke",
                COLLECTOR_CREDENTIAL_HEADER: "device-secret-900",
            },
        )
        self.assertEqual(denied_batch.status_code, 403)

        denied_recovery = self.client.post(
            "/api/collector/v1/recover",
            json={
                "collector_id": collector_id,
                "hostname": hostname,
                "recovery_id": "recovery-2",
                "new_credential": "device-secret-901",
            },
            headers={
                RECOVERY_TOKEN_HEADER: "recovery-secret",
            },
        )
        self.assertEqual(denied_recovery.status_code, 403)


if __name__ == "__main__":
    unittest.main()
