import sqlite3
import tempfile
import unittest
from pathlib import Path

from flask import Flask

from backend.analyzer.collector_api import (
    COLLECTOR_CREDENTIAL_HEADER,
    ENROLLMENT_TOKEN_HEADER,
    create_collector_blueprint,
)
from backend.storage.collector_identity import (
    certificate_fingerprint_from_pem,
)
from backend.storage.migrations import ensure_platform_schema

CERT_A = """-----BEGIN CERTIFICATE-----
AQIDBA==
-----END CERTIFICATE-----"""
CERT_B = """-----BEGIN CERTIFICATE-----
BQYHCA==
-----END CERTIFICATE-----"""
CERT_C = """-----BEGIN CERTIFICATE-----
CQoLDA==
-----END CERTIFICATE-----"""

class CollectorCertificateRotationServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "server.db"

        def connection_factory():
            conn = sqlite3.connect(str(self.db_path), timeout=30)
            ensure_platform_schema(conn)
            return conn

        self.connection_factory = connection_factory
        app = Flask(__name__)
        app.register_blueprint(
            create_collector_blueprint(
                self.connection_factory,
                auth_required=True,
                enrollment_token="bootstrap-secret",
                credential_factory=lambda: "device-secret-001",
                mtls_required=True,
            )
        )
        app.testing = True
        self.client = app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def env(cert):
        return {"SSL_CLIENT_VERIFY": "SUCCESS", "SSL_CLIENT_CERT": cert}

    def enroll(self):
        return self.client.post(
            "/api/collector/v1/enroll",
            json={"collector_id": "collector-1", "hostname": "HOST01"},
            headers={ENROLLMENT_TOKEN_HEADER: "bootstrap-secret"},
            environ_overrides=self.env(CERT_A),
        )

    def stage(self, cert=CERT_A, new_cert=CERT_B, rotation_id="cert-rot-1"):
        return self.client.post(
            "/api/collector/v1/certificate/rotate",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "certificate_rotation_id": rotation_id,
                "new_certificate_fingerprint": certificate_fingerprint_from_pem(new_cert),
            },
            headers={
                "X-AegisGuard-Collector-ID": "collector-1",
                COLLECTOR_CREDENTIAL_HEADER: "device-secret-001",
            },
            environ_overrides=self.env(cert),
        )

    def batch(self, batch_id, cert):
        return self.client.post(
            "/api/collector/v1/batches",
            json={
                "batch_id": batch_id,
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "os": "Windows",
                "logs": [{"record_id": 101}],
            },
            headers={
                "X-AegisGuard-Collector-ID": "collector-1",
                "X-AegisGuard-Batch-ID": batch_id,
                COLLECTOR_CREDENTIAL_HEADER: "device-secret-001",
            },
            environ_overrides=self.env(cert),
        )

    def row(self):
        conn = self.connection_factory()
        try:
            return conn.execute(
                """
                SELECT certificate_fingerprint,
                       pending_certificate_fingerprint,
                       certificate_rotation_id,
                       certificate_rotation_started_at,
                       certificate_rotated_at
                FROM collectors
                WHERE collector_id='collector-1'
                """
            ).fetchone()
        finally:
            conn.close()

    def test_stage_keeps_current_certificate_valid(self):
        self.assertEqual(self.enroll().status_code, 201)
        response = self.stage()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.get_json()["duplicate"])
        row = self.row()
        self.assertEqual(row[0], certificate_fingerprint_from_pem(CERT_A))
        self.assertEqual(row[1], certificate_fingerprint_from_pem(CERT_B))
        self.assertEqual(row[2], "cert-rot-1")
        self.assertIsNotNone(row[3])
        self.assertEqual(self.batch("batch-current", CERT_A).status_code, 202)

    def test_pending_certificate_promotes_on_first_successful_use(self):
        self.assertEqual(self.enroll().status_code, 201)
        self.assertEqual(self.stage().status_code, 200)
        self.assertEqual(self.batch("batch-new", CERT_B).status_code, 202)
        row = self.row()
        self.assertEqual(row[0], certificate_fingerprint_from_pem(CERT_B))
        self.assertIsNone(row[1])
        self.assertEqual(row[2], "cert-rot-1")
        self.assertIsNone(row[3])
        self.assertIsNotNone(row[4])
        self.assertEqual(self.batch("batch-old", CERT_A).status_code, 401)

    def test_same_rotation_replay_is_idempotent(self):
        self.assertEqual(self.enroll().status_code, 201)
        self.assertEqual(self.stage().status_code, 200)
        replay = self.stage()
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.get_json()["duplicate"])

    def test_rotation_id_reuse_with_different_certificate_conflicts(self):
        self.assertEqual(self.enroll().status_code, 201)
        self.assertEqual(self.stage().status_code, 200)
        self.assertEqual(self.stage(new_cert=CERT_C).status_code, 409)

    def test_unstaged_certificate_is_rejected(self):
        self.assertEqual(self.enroll().status_code, 201)
        self.assertEqual(self.batch("batch-unstaged", CERT_B).status_code, 401)

    def test_wrong_current_certificate_cannot_stage_rotation(self):
        self.assertEqual(self.enroll().status_code, 201)
        self.assertEqual(self.stage(cert=CERT_B).status_code, 401)

    def test_completed_rotation_replay_is_idempotent_with_new_certificate(self):
        self.assertEqual(self.enroll().status_code, 201)
        self.assertEqual(self.stage().status_code, 200)
        self.assertEqual(self.batch("batch-new", CERT_B).status_code, 202)
        replay = self.stage(cert=CERT_B)
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.get_json()["duplicate"])
        self.assertTrue(replay.get_json()["completed"])

if __name__ == "__main__":
    unittest.main()
