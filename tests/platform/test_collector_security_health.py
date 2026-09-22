import json
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
from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.storage.collector_health import get_collector_health
from backend.storage.migrations import ensure_platform_schema


CERT_A = """-----BEGIN CERTIFICATE-----
AQIDBA==
-----END CERTIFICATE-----"""


class _HealthRuntimeState:
    def get_active_client_certificate_reference(self):
        return None

    def get_pending_client_certificate_rotation(self):
        return None

    def get_or_create_collector_id(self):
        return "collector-1"

    def get_collector_credential(self):
        return "device-secret-001"

    def transport_health(self, now=None):
        return {
            "status": "RETRY_WAIT",
            "collector_id": "collector-1",
            "checkpoint": 100,
            "collection_cursor": 130,
            "pending_batches": 3,
            "oldest_pending_age_seconds": 15.0,
            "oldest_pending_batch_id": "batch-1",
            "oldest_pending_attempts": 2,
            "total_attempts": 4,
            "last_error": "offline",
            "last_attempt_at": 1000.0,
            "next_attempt_at": 1010.0,
            "retry_in_seconds": 10.0,
            "last_successful_ack_at": 900.0,
        }


class CollectorSecurityHealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "server.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection_factory(self):
        conn = sqlite3.connect(str(self.db_path))
        ensure_platform_schema(conn)
        return conn

    def make_client(self, *, mtls_required=False):
        app = Flask(__name__)
        app.register_blueprint(
            create_collector_blueprint(
                self.connection_factory,
                auth_required=True,
                enrollment_token="bootstrap-secret",
                credential_factory=lambda: "device-secret-001",
                mtls_required=mtls_required,
            )
        )
        app.testing = True
        return app.test_client()

    @staticmethod
    def mtls_env():
        return {
            "SSL_CLIENT_VERIFY": "SUCCESS",
            "SSL_CLIENT_CERT": CERT_A,
        }

    def enroll(self, client, *, mtls=False):
        kwargs = {}
        if mtls:
            kwargs["environ_overrides"] = self.mtls_env()
        return client.post(
            "/api/collector/v1/enroll",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "version": "0.1.0",
            },
            headers={
                ENROLLMENT_TOKEN_HEADER: "bootstrap-secret",
            },
            **kwargs,
        )

    @staticmethod
    def headers():
        return {
            "X-AegisGuard-Collector-ID": "collector-1",
            COLLECTOR_CREDENTIAL_HEADER: "device-secret-001",
        }

    def test_persists_server_trust_and_reported_operational_health(self):
        client = self.make_client(mtls_required=True)
        self.assertEqual(
            self.enroll(client, mtls=True).status_code,
            201,
        )

        response = client.post(
            "/api/collector/v1/heartbeat",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "version": "0.1.7",
                "health": {
                    "status": "RETRY_WAIT",
                    "pending_batches": 3,
                    "checkpoint": 100,
                    "collection_cursor": 130,
                    "retry_in_seconds": 12.5,
                    "last_successful_ack_at": 12345.5,
                    "certificate_rotation_pending": True,
                },
            },
            headers=self.headers(),
            environ_overrides={
                **self.mtls_env(),
                "REMOTE_ADDR": "203.0.113.9",
            },
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["last_heartbeat_at"])
        self.assertTrue(
            body["server_observed"]["credential_authenticated"]
        )
        self.assertTrue(body["server_observed"]["mtls_required"])
        self.assertTrue(body["server_observed"]["mtls_verified"])

        conn = self.connection_factory()
        try:
            health = get_collector_health(conn, "collector-1")
        finally:
            conn.close()

        observed = health["server_observed"]
        reported = health["collector_reported"]

        self.assertEqual(observed["peer_ip"], "203.0.113.9")
        self.assertTrue(observed["credential_authenticated"])
        self.assertTrue(observed["mtls_required"])
        self.assertTrue(observed["mtls_verified"])
        self.assertTrue(observed["certificate_fingerprint"])

        self.assertEqual(reported["version"], "0.1.7")
        self.assertEqual(reported["transport_status"], "RETRY_WAIT")
        self.assertEqual(reported["pending_batches"], 3)
        self.assertEqual(reported["checkpoint"], 100)
        self.assertEqual(reported["collection_cursor"], 130)
        self.assertEqual(reported["retry_in_seconds"], 12.5)
        self.assertEqual(
            reported["last_successful_ack_at"],
            12345.5,
        )
        self.assertTrue(reported["certificate_rotation_pending"])

    def test_client_security_claims_cannot_spoof_server_observations(self):
        client = self.make_client()
        self.assertEqual(self.enroll(client).status_code, 201)

        response = client.post(
            "/api/collector/v1/heartbeat",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "health": {
                    "status": "HEALTHY",
                    "pending_batches": 0,
                    "mtls_verified": True,
                    "credential_authenticated": False,
                    "certificate_fingerprint": "f" * 64,
                },
            },
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 200)

        conn = self.connection_factory()
        try:
            health = get_collector_health(conn, "collector-1")
            raw_json = conn.execute(
                """
                SELECT reported_health_json
                FROM collectors
                WHERE collector_id='collector-1'
                """
            ).fetchone()[0]
        finally:
            conn.close()

        observed = health["server_observed"]
        self.assertTrue(observed["credential_authenticated"])
        self.assertFalse(observed["mtls_required"])
        self.assertFalse(observed["mtls_verified"])
        self.assertIsNone(observed["certificate_fingerprint"])

        raw = json.loads(raw_json)
        self.assertNotIn("mtls_verified", raw)
        self.assertNotIn("credential_authenticated", raw)
        self.assertNotIn("certificate_fingerprint", raw)

    def test_invalid_health_is_rejected_without_heartbeat_record(self):
        client = self.make_client()
        self.assertEqual(self.enroll(client).status_code, 201)

        response = client.post(
            "/api/collector/v1/heartbeat",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "health": {
                    "status": "COMPROMISED",
                    "pending_batches": -1,
                },
            },
            headers=self.headers(),
        )

        self.assertEqual(response.status_code, 400)

        conn = self.connection_factory()
        try:
            row = conn.execute(
                """
                SELECT last_heartbeat_at
                FROM collectors
                WHERE collector_id='collector-1'
                """
            ).fetchone()
        finally:
            conn.close()

        self.assertIsNone(row[0])

    def test_runtime_sends_sanitized_operational_subset(self):
        captured = {}

        class Response:
            status_code = 200

            @staticmethod
            def json():
                return {
                    "status": "alive",
                    "collector_id": "collector-1",
                    "hostname": "HOST01",
                    "last_seen_at": "2026-09-22 12:30:00",
                }

        def sender(url, payload, credential, **kwargs):
            captured["payload"] = payload
            captured["credential"] = credential
            return Response()

        runtime = DurableCollectorRuntime(
            _HealthRuntimeState(),
            "https://siem.example.test/api/collector/v1/batches",
            heartbeat_url=(
                "https://siem.example.test/api/collector/v1/heartbeat"
            ),
            hostname="HOST01",
            os_name="Windows-11",
            auth_required=True,
            collector_version="0.1.0",
            heartbeat_sender=sender,
            clock=lambda: 1000.0,
        )

        body = runtime.heartbeat()
        self.assertEqual(body["status"], "alive")

        report = captured["payload"]["health"]
        self.assertEqual(report["status"], "RETRY_WAIT")
        self.assertEqual(report["pending_batches"], 3)
        self.assertEqual(report["checkpoint"], 100)
        self.assertEqual(report["collection_cursor"], 130)
        self.assertEqual(report["retry_in_seconds"], 10.0)
        self.assertEqual(report["last_successful_ack_at"], 900.0)
        self.assertFalse(report["certificate_rotation_pending"])

        self.assertNotIn("analyzer_url", report)
        self.assertNotIn("auth_required", report)
        self.assertNotIn("mtls_required", report)
        self.assertNotIn("mtls_configured", report)
        self.assertNotIn("enrolled", report)
        self.assertNotIn("last_error", report)

    def test_heartbeat_health_does_not_create_ingest_batches(self):
        client = self.make_client()
        self.assertEqual(self.enroll(client).status_code, 201)

        response = client.post(
            "/api/collector/v1/heartbeat",
            json={
                "collector_id": "collector-1",
                "hostname": "HOST01",
                "health": {
                    "status": "BACKLOG",
                    "pending_batches": 2,
                },
            },
            headers=self.headers(),
        )
        self.assertEqual(response.status_code, 200)

        conn = self.connection_factory()
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM collector_ingest_batches"
            ).fetchone()[0]
        finally:
            conn.close()

        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
