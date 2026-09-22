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
from backend.collector.state import CollectorState
from backend.storage.collector_identity import (
    certificate_fingerprint_from_pem,
    revoke_collector,
)
from backend.storage.migrations import ensure_platform_schema


CERT_A = """-----BEGIN CERTIFICATE-----
AQIDBA==
-----END CERTIFICATE-----"""
CERT_B = """-----BEGIN CERTIFICATE-----
BQYHCA==
-----END CERTIFICATE-----"""


class _TestProtector:
    PREFIX = b"TEST-PROTECTED:"

    def protect(self, plaintext: bytes) -> bytes:
        return self.PREFIX + bytes(plaintext)[::-1]

    def unprotect(self, protected: bytes) -> bytes:
        value = bytes(protected)
        if not value.startswith(self.PREFIX):
            raise ValueError("invalid test credential")
        return value[len(self.PREFIX):][::-1]


class S34SecurityEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server_db = Path(self.tmp.name) / "server.db"

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
        return {
            "SSL_CLIENT_VERIFY": "SUCCESS",
            "SSL_CLIENT_CERT": cert,
        }

    @staticmethod
    def auth_headers(credential):
        return {
            "X-AegisGuard-Collector-ID": "collector-1",
            COLLECTOR_CREDENTIAL_HEADER: credential,
        }

    def heartbeat(self, cert, credential):
        return self.client.post(
            "/api/collector/v1/heartbeat",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "version": "0.1.0",
                "health": {
                    "status": "HEALTHY",
                    "pending_batches": 0,
                    "checkpoint": 101,
                    "collection_cursor": 101,
                    "certificate_rotation_pending": False,
                },
            },
            headers=self.auth_headers(credential),
            environ_overrides=self.env(cert),
        )

    def batch(self, batch_id, cert, credential):
        headers = self.auth_headers(credential)
        headers["X-AegisGuard-Batch-ID"] = batch_id
        return self.client.post(
            "/api/collector/v1/batches",
            json={
                "batch_id": batch_id,
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "os": "Windows-11",
                "logs": [
                    {
                        "record_id": 101,
                        "event_type": "FAILED_LOGIN",
                    }
                ],
            },
            headers=headers,
            environ_overrides=self.env(cert),
        )

    def batch_count(self):
        conn = self.connection_factory()
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM collector_ingest_batches"
            ).fetchone()[0]
        finally:
            conn.close()

    def test_full_security_lifecycle_closes_fail_closed(self):
        enrolled = self.client.post(
            "/api/collector/v1/enroll",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "version": "0.1.0",
            },
            headers={
                ENROLLMENT_TOKEN_HEADER: "bootstrap-secret",
            },
            environ_overrides=self.env(CERT_A),
        )
        self.assertEqual(enrolled.status_code, 201)
        credential_a = enrolled.get_json()["credential"]
        self.assertEqual(credential_a, "device-secret-001")

        first_heartbeat = self.heartbeat(CERT_A, credential_a)
        self.assertEqual(first_heartbeat.status_code, 200)
        heartbeat_body = first_heartbeat.get_json()
        self.assertTrue(
            heartbeat_body["server_observed"]["credential_authenticated"]
        )
        self.assertTrue(
            heartbeat_body["server_observed"]["mtls_verified"]
        )

        first_batch = self.batch("batch-1", CERT_A, credential_a)
        self.assertEqual(first_batch.status_code, 202)
        self.assertFalse(first_batch.get_json()["duplicate"])

        duplicate_batch = self.batch("batch-1", CERT_A, credential_a)
        self.assertEqual(duplicate_batch.status_code, 202)
        self.assertTrue(duplicate_batch.get_json()["duplicate"])
        self.assertEqual(self.batch_count(), 1)

        credential_b = "device-secret-002"
        rotated = self.client.post(
            "/api/collector/v1/rotate",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "rotation_id": "credential-rotation-1",
                "new_credential": credential_b,
            },
            headers=self.auth_headers(credential_a),
            environ_overrides=self.env(CERT_A),
        )
        self.assertEqual(rotated.status_code, 200)

        self.assertEqual(
            self.heartbeat(CERT_A, credential_a).status_code,
            401,
        )
        self.assertEqual(
            self.heartbeat(CERT_A, credential_b).status_code,
            200,
        )

        cert_rotated = self.client.post(
            "/api/collector/v1/certificate/rotate",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "certificate_rotation_id": "certificate-rotation-1",
                "new_certificate_fingerprint": (
                    certificate_fingerprint_from_pem(CERT_B)
                ),
            },
            headers=self.auth_headers(credential_b),
            environ_overrides=self.env(CERT_A),
        )
        self.assertEqual(cert_rotated.status_code, 200)

        promoted = self.heartbeat(CERT_B, credential_b)
        self.assertEqual(promoted.status_code, 200)

        self.assertEqual(
            self.heartbeat(CERT_A, credential_b).status_code,
            401,
        )

        conn = self.connection_factory()
        try:
            row = conn.execute(
                """
                SELECT certificate_fingerprint,
                       pending_certificate_fingerprint,
                       heartbeat_mtls_verified,
                       last_heartbeat_at
                FROM collectors
                WHERE collector_id='collector-1'
                """
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(
            row[0],
            certificate_fingerprint_from_pem(CERT_B),
        )
        self.assertIsNone(row[1])
        self.assertEqual(row[2], 1)
        self.assertIsNotNone(row[3])

        conn = self.connection_factory()
        try:
            self.assertTrue(
                revoke_collector(
                    conn,
                    "collector-1",
                    revoked_at="2026-09-22T12:00:00Z",
                )
            )
        finally:
            conn.close()

        self.assertEqual(
            self.heartbeat(CERT_B, credential_b).status_code,
            403,
        )
        self.assertEqual(
            self.batch("batch-after-revoke", CERT_B, credential_b).status_code,
            403,
        )
        self.assertEqual(self.batch_count(), 1)

    def test_restart_preserves_durable_security_and_transport_state(self):
        path = Path(self.tmp.name) / "collector-state.db"
        protector = _TestProtector()

        first = CollectorState(
            path,
            credential_protector=protector,
        )
        collector_id = first.get_or_create_collector_id()
        first.store_collector_credential("device-secret-002")
        first.initialize_checkpoint(101)
        first.enqueue(
            {
                "batch_id": "pending-batch-1",
                "collector_id": collector_id,
                "hostname": "HOST01",
                "os": "Windows-11",
                "logs": [{"record_id": 102}],
            },
            102,
        )
        first.begin_client_certificate_rotation(
            "certificate-rotation-pending",
            ("C:/AegisGuard/client-b.pem", "C:/AegisGuard/client-b.key"),
            "b" * 64,
        )
        first.mark_client_certificate_rotation_staged(
            "certificate-rotation-pending"
        )

        restarted = CollectorState(
            path,
            credential_protector=protector,
        )

        self.assertEqual(
            restarted.get_or_create_collector_id(),
            collector_id,
        )
        self.assertEqual(
            restarted.get_collector_credential(),
            "device-secret-002",
        )
        self.assertEqual(restarted.get_checkpoint(), 101)
        self.assertEqual(restarted.get_collection_cursor(), 102)

        pending_batches = restarted.pending()
        self.assertEqual(len(pending_batches), 1)
        self.assertEqual(
            pending_batches[0]["batch_id"],
            "pending-batch-1",
        )

        pending_cert = (
            restarted.get_pending_client_certificate_rotation()
        )
        self.assertEqual(
            pending_cert["rotation_id"],
            "certificate-rotation-pending",
        )
        self.assertTrue(pending_cert["staged"])
        self.assertEqual(
            pending_cert["client_cert"],
            (
                "C:/AegisGuard/client-b.pem",
                "C:/AegisGuard/client-b.key",
            ),
        )


if __name__ == "__main__":
    unittest.main()
