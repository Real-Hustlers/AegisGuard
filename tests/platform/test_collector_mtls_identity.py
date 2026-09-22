import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from flask import Flask

from backend.analyzer.collector_api import (
    COLLECTOR_CREDENTIAL_HEADER,
    ENROLLMENT_TOKEN_HEADER,
    RECOVERY_TOKEN_HEADER,
    create_collector_blueprint,
)
from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.transport import (
    build_batch_payload,
    build_enrollment_payload,
    send_batch,
    send_enrollment,
)
from backend.storage.collector_identity import (
    certificate_fingerprint_from_pem,
    credential_fingerprint,
)
from backend.storage.migrations import ensure_platform_schema


CERT_A = """-----BEGIN CERTIFICATE-----
AQIDBA==
-----END CERTIFICATE-----"""
CERT_B = """-----BEGIN CERTIFICATE-----
BQYHCA==
-----END CERTIFICATE-----"""


class CollectorMtlsIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "server.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection_factory(self):
        conn = sqlite3.connect(str(self.db_path))
        ensure_platform_schema(conn)
        return conn

    def make_client(self, *, mtls_required=True):
        app = Flask(__name__)
        app.register_blueprint(
            create_collector_blueprint(
                self.connection_factory,
                auth_required=True,
                enrollment_token="bootstrap-secret",
                recovery_token="recovery-secret",
                credential_factory=lambda: "device-secret-001",
                mtls_required=mtls_required,
            )
        )
        app.testing = True
        return app.test_client()

    @staticmethod
    def mtls_env(cert):
        return {"SSL_CLIENT_VERIFY": "SUCCESS", "SSL_CLIENT_CERT": cert}

    @staticmethod
    def enrollment_payload():
        return {
            "collector_id": "collector-1",
            "hostname": "HOST01",
            "version": "0.1.0",
            "metadata": {"os": "Windows-11"},
        }

    def enroll(self, client, cert=CERT_A):
        return client.post(
            "/api/collector/v1/enroll",
            json=self.enrollment_payload(),
            headers={ENROLLMENT_TOKEN_HEADER: "bootstrap-secret"},
            environ_overrides=self.mtls_env(cert),
        )

    def test_certificate_fingerprint_is_sha256_of_der(self):
        self.assertEqual(
            certificate_fingerprint_from_pem(CERT_A),
            "9f64a747e1b97f131fabb6b447296c9b6"
            "f0201e79fb3c5356e6c77e89b6a806a",
        )

    def test_enrollment_requires_verified_client_certificate(self):
        client = self.make_client()
        missing = client.post(
            "/api/collector/v1/enroll",
            json=self.enrollment_payload(),
            headers={ENROLLMENT_TOKEN_HEADER: "bootstrap-secret"},
        )
        self.assertEqual(missing.status_code, 401)

        failed = client.post(
            "/api/collector/v1/enroll",
            json=self.enrollment_payload(),
            headers={ENROLLMENT_TOKEN_HEADER: "bootstrap-secret"},
            environ_overrides={
                "SSL_CLIENT_VERIFY": "FAILED",
                "SSL_CLIENT_CERT": CERT_A,
            },
        )
        self.assertEqual(failed.status_code, 401)

    def test_enrollment_binds_certificate_fingerprint(self):
        client = self.make_client()
        self.assertEqual(self.enroll(client).status_code, 201)

        conn = self.connection_factory()
        try:
            row = conn.execute(
                """
                SELECT credential_fingerprint,
                       certificate_fingerprint,
                       certificate_bound_at
                FROM collectors
                WHERE collector_id='collector-1'
                """
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(
            row[0], credential_fingerprint("device-secret-001")
        )
        self.assertEqual(
            row[1], certificate_fingerprint_from_pem(CERT_A)
        )
        self.assertIsNotNone(row[2])

    def test_wrong_certificate_fails_before_batch_persistence(self):
        client = self.make_client()
        self.assertEqual(self.enroll(client).status_code, 201)
        payload = {
            "batch_id": "batch-1",
            "collector_id": "collector-1",
            "hostname": "HOST01",
            "os": "Windows",
            "logs": [{"record_id": 101}],
        }
        headers = {
            "X-AegisGuard-Collector-ID": "collector-1",
            "X-AegisGuard-Batch-ID": "batch-1",
            COLLECTOR_CREDENTIAL_HEADER: "device-secret-001",
        }

        wrong = client.post(
            "/api/collector/v1/batches",
            json=payload,
            headers=headers,
            environ_overrides=self.mtls_env(CERT_B),
        )
        self.assertEqual(wrong.status_code, 401)

        conn = self.connection_factory()
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM collector_ingest_batches"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 0)

        accepted = client.post(
            "/api/collector/v1/batches",
            json=payload,
            headers=headers,
            environ_overrides=self.mtls_env(CERT_A),
        )
        self.assertEqual(accepted.status_code, 202)

    def test_recovery_requires_bound_certificate(self):
        client = self.make_client()
        self.assertEqual(self.enroll(client).status_code, 201)
        payload = {
            "collector_id": "collector-1",
            "hostname": "HOST01",
            "recovery_id": "recovery-1",
            "new_credential": "device-secret-900",
        }

        wrong = client.post(
            "/api/collector/v1/recover",
            json=payload,
            headers={RECOVERY_TOKEN_HEADER: "recovery-secret"},
            environ_overrides=self.mtls_env(CERT_B),
        )
        self.assertEqual(wrong.status_code, 401)

        good = client.post(
            "/api/collector/v1/recover",
            json=payload,
            headers={RECOVERY_TOKEN_HEADER: "recovery-secret"},
            environ_overrides=self.mtls_env(CERT_A),
        )
        self.assertEqual(good.status_code, 200)

    def test_transport_presents_client_certificate(self):
        session = Mock()
        enrollment_payload = build_enrollment_payload(
            "collector-1", "HOST01", "Windows-11"
        )
        session.post.return_value = Mock(status_code=201)
        send_enrollment(
            "https://siem.example.test/api/collector/v1/enroll",
            enrollment_payload,
            "bootstrap-secret",
            ca_bundle="C:/AegisGuard/ca.pem",
            client_cert=(
                "C:/AegisGuard/client-cert.pem",
                "C:/AegisGuard/client-key.pem",
            ),
            session=session,
        )
        _, kwargs = session.post.call_args
        self.assertEqual(
            kwargs["cert"],
            (
                "C:/AegisGuard/client-cert.pem",
                "C:/AegisGuard/client-key.pem",
            ),
        )
        self.assertEqual(kwargs["verify"], "C:/AegisGuard/ca.pem")

        session.reset_mock()
        session.post.return_value = Mock(status_code=202)
        batch = build_batch_payload(
            "collector-1",
            "HOST01",
            "Windows-11",
            [],
            batch_id="batch-1",
        )
        send_batch(
            "https://siem.example.test/api/collector/v1/batches",
            batch,
            credential="device-secret-001",
            client_cert="C:/AegisGuard/client-combined.pem",
            session=session,
        )
        _, kwargs = session.post.call_args
        self.assertEqual(
            kwargs["cert"], "C:/AegisGuard/client-combined.pem"
        )

    def test_runtime_requires_certificate_when_mtls_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text("{}", encoding="utf-8")
            config = {
                "collector_ingest_url":
                    "https://siem.example.test/api/collector/v1/batches",
                "collector_enrollment_url":
                    "https://siem.example.test/api/collector/v1/enroll",
                "collector_auth_required": True,
                "collector_mtls_required": True,
                "collector_state_file": "collector-state.db",
            }

            with self.assertRaisesRegex(
                ValueError, "client certificate"
            ):
                DurableCollectorRuntime.from_config(
                    config,
                    config_path,
                    hostname="HOST01",
                    os_name="Windows-11",
                )

            config["collector_client_certificate"] = "client-cert.pem"
            config["collector_client_key"] = "client-key.pem"
            runtime = DurableCollectorRuntime.from_config(
                config,
                config_path,
                hostname="HOST01",
                os_name="Windows-11",
            )
            self.assertTrue(runtime.mtls_required)
            self.assertTrue(runtime.health_snapshot()["mtls_configured"])


if __name__ == "__main__":
    unittest.main()
