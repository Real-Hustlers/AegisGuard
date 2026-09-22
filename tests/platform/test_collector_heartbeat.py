import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from flask import Flask

from backend.analyzer.collector_api import (
    COLLECTOR_CREDENTIAL_HEADER,
    ENROLLMENT_TOKEN_HEADER,
    create_collector_blueprint,
)
from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.transport import (
    build_heartbeat_payload,
    send_heartbeat,
    validate_heartbeat_response,
)
from backend.storage.collector_identity import revoke_collector
from backend.storage.migrations import ensure_platform_schema


CERT_A = """-----BEGIN CERTIFICATE-----
AQIDBA==
-----END CERTIFICATE-----"""
CERT_B = """-----BEGIN CERTIFICATE-----
BQYHCA==
-----END CERTIFICATE-----"""


class _RuntimeState:
    def __init__(self):
        self.credential = "device-secret-001"

    def get_active_client_certificate_reference(self):
        return None

    def get_pending_client_certificate_rotation(self):
        return None

    def get_or_create_collector_id(self):
        return "collector-1"

    def get_collector_credential(self):
        return self.credential


class CollectorHeartbeatTests(unittest.TestCase):
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
    def mtls_env(cert):
        return {
            "SSL_CLIENT_VERIFY": "SUCCESS",
            "SSL_CLIENT_CERT": cert,
        }

    def enroll(self, client, *, cert=None):
        kwargs = {}
        if cert is not None:
            kwargs["environ_overrides"] = self.mtls_env(cert)
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
    def heartbeat_payload():
        return {
            "collector_id": "collector-1",
            "hostname": "HOST01",
            "version": "0.1.0",
        }

    @staticmethod
    def heartbeat_headers(credential="device-secret-001"):
        headers = {
            "X-AegisGuard-Collector-ID": "collector-1",
        }
        if credential is not None:
            headers[COLLECTOR_CREDENTIAL_HEADER] = credential
        return headers

    def batch_count(self):
        conn = self.connection_factory()
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM collector_ingest_batches"
            ).fetchone()[0]
        finally:
            conn.close()

    def test_valid_heartbeat_authenticates_updates_last_seen_without_ingestion(self):
        client = self.make_client()
        self.assertEqual(self.enroll(client).status_code, 201)

        response = client.post(
            "/api/collector/v1/heartbeat",
            json=self.heartbeat_payload(),
            headers=self.heartbeat_headers(),
        )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertEqual(body["status"], "alive")
        self.assertEqual(body["collector_id"], "collector-1")
        self.assertEqual(body["hostname"], "HOST01")
        self.assertTrue(body["last_seen_at"])
        self.assertEqual(self.batch_count(), 0)

        conn = self.connection_factory()
        try:
            last_seen = conn.execute(
                """
                SELECT last_seen_at
                FROM collectors
                WHERE collector_id='collector-1'
                """
            ).fetchone()[0]
        finally:
            conn.close()

        self.assertEqual(last_seen, body["last_seen_at"])

    def test_heartbeat_rejects_missing_and_wrong_credentials(self):
        client = self.make_client()
        self.assertEqual(self.enroll(client).status_code, 201)

        missing = client.post(
            "/api/collector/v1/heartbeat",
            json=self.heartbeat_payload(),
            headers=self.heartbeat_headers(None),
        )
        self.assertEqual(missing.status_code, 401)

        wrong = client.post(
            "/api/collector/v1/heartbeat",
            json=self.heartbeat_payload(),
            headers=self.heartbeat_headers("wrong-secret"),
        )
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(self.batch_count(), 0)

    def test_heartbeat_rejects_hostname_mismatch(self):
        client = self.make_client()
        self.assertEqual(self.enroll(client).status_code, 201)

        payload = self.heartbeat_payload()
        payload["hostname"] = "OTHER-HOST"

        response = client.post(
            "/api/collector/v1/heartbeat",
            json=payload,
            headers=self.heartbeat_headers(),
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.batch_count(), 0)

    def test_heartbeat_rejects_revoked_collector(self):
        client = self.make_client()
        self.assertEqual(self.enroll(client).status_code, 201)

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

        response = client.post(
            "/api/collector/v1/heartbeat",
            json=self.heartbeat_payload(),
            headers=self.heartbeat_headers(),
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.batch_count(), 0)

    def test_heartbeat_requires_bound_certificate_when_mtls_enabled(self):
        client = self.make_client(mtls_required=True)
        self.assertEqual(
            self.enroll(client, cert=CERT_A).status_code,
            201,
        )

        wrong = client.post(
            "/api/collector/v1/heartbeat",
            json=self.heartbeat_payload(),
            headers=self.heartbeat_headers(),
            environ_overrides=self.mtls_env(CERT_B),
        )
        self.assertEqual(wrong.status_code, 401)

        accepted = client.post(
            "/api/collector/v1/heartbeat",
            json=self.heartbeat_payload(),
            headers=self.heartbeat_headers(),
            environ_overrides=self.mtls_env(CERT_A),
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(self.batch_count(), 0)

    def test_heartbeat_transport_uses_credential_ca_and_client_certificate(self):
        session = Mock()
        response = Mock(status_code=200)
        response.json.return_value = {
            "status": "alive",
            "collector_id": "collector-1",
            "hostname": "HOST01",
            "last_seen_at": "2026-09-22 12:30:00",
        }
        session.post.return_value = response

        payload = build_heartbeat_payload(
            "collector-1",
            "HOST01",
            version="0.1.0",
        )
        result = send_heartbeat(
            "https://siem.example.test/api/collector/v1/heartbeat",
            payload,
            "device-secret-001",
            ca_bundle="C:/AegisGuard/ca.pem",
            client_cert=(
                "C:/AegisGuard/client.pem",
                "C:/AegisGuard/client.key",
            ),
            session=session,
        )

        _, kwargs = session.post.call_args
        self.assertEqual(
            kwargs["headers"][COLLECTOR_CREDENTIAL_HEADER],
            "device-secret-001",
        )
        self.assertEqual(
            kwargs["headers"]["X-AegisGuard-Collector-ID"],
            "collector-1",
        )
        self.assertEqual(kwargs["verify"], "C:/AegisGuard/ca.pem")
        self.assertEqual(
            kwargs["cert"],
            (
                "C:/AegisGuard/client.pem",
                "C:/AegisGuard/client.key",
            ),
        )
        self.assertEqual(
            validate_heartbeat_response(result, payload)["status"],
            "alive",
        )

    def test_runtime_heartbeat_uses_enrolled_credential(self):
        sender = Mock()
        response = Mock(status_code=200)
        response.json.return_value = {
            "status": "alive",
            "collector_id": "collector-1",
            "hostname": "HOST01",
            "last_seen_at": "2026-09-22 12:30:00",
        }
        sender.return_value = response

        runtime = DurableCollectorRuntime(
            _RuntimeState(),
            "https://siem.example.test/api/collector/v1/batches",
            heartbeat_url=(
                "https://siem.example.test/api/collector/v1/heartbeat"
            ),
            ca_bundle="C:/AegisGuard/ca.pem",
            hostname="HOST01",
            os_name="Windows-11",
            client_cert=(
                "C:/AegisGuard/client.pem",
                "C:/AegisGuard/client.key",
            ),
            mtls_required=True,
            auth_required=True,
            collector_version="0.1.0",
            heartbeat_sender=sender,
        )

        body = runtime.heartbeat()

        self.assertEqual(body["status"], "alive")
        args, kwargs = sender.call_args
        self.assertEqual(
            args[0],
            "https://siem.example.test/api/collector/v1/heartbeat",
        )
        self.assertEqual(args[2], "device-secret-001")
        self.assertEqual(kwargs["ca_bundle"], "C:/AegisGuard/ca.pem")
        self.assertEqual(
            kwargs["client_cert"],
            (
                "C:/AegisGuard/client.pem",
                "C:/AegisGuard/client.key",
            ),
        )


if __name__ == "__main__":
    unittest.main()
