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
    credential_fingerprint,
    revoke_collector,
)
from backend.storage.migrations import ensure_platform_schema


class CollectorAuthenticationApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "server.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection_factory(self):
        conn = sqlite3.connect(str(self.db_path))
        ensure_platform_schema(conn)
        return conn

    def make_client(
        self,
        *,
        auth_required=False,
        enrollment_token=None,
        credential_factory=None,
    ):
        app = Flask(__name__)
        app.register_blueprint(
            create_collector_blueprint(
                self.connection_factory,
                auth_required=auth_required,
                enrollment_token=enrollment_token,
                credential_factory=credential_factory,
            )
        )
        app.testing = True
        return app.test_client()

    @staticmethod
    def payload():
        return {
            "batch_id": "batch-1",
            "collector_id": "collector-1",
            "hostname": "HOST01",
            "os": "Windows",
            "logs": [
                {
                    "record_id": 101,
                    "event_type": "LOGON_FAILURE",
                }
            ],
        }

    @staticmethod
    def batch_headers(credential=None):
        headers = {
            "X-AegisGuard-Collector-ID": "collector-1",
            "X-AegisGuard-Batch-ID": "batch-1",
        }
        if credential is not None:
            headers[COLLECTOR_CREDENTIAL_HEADER] = credential
        return headers

    def enroll(
        self,
        client,
        *,
        token="bootstrap-secret",
        collector_id="collector-1",
        hostname="HOST01",
    ):
        return client.post(
            "/api/collector/v1/enroll",
            json={
                "collector_id": collector_id,
                "hostname": hostname,
                "version": "0.1.0",
                "metadata": {"os": "Windows-11"},
            },
            headers={ENROLLMENT_TOKEN_HEADER: token},
        )

    def batch_count(self):
        conn = self.connection_factory()
        try:
            return conn.execute(
                "SELECT COUNT(*) FROM collector_ingest_batches"
            ).fetchone()[0]
        finally:
            conn.close()

    def test_enrollment_is_disabled_without_bootstrap_token(self):
        client = self.make_client()

        response = self.enroll(client)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["status"], "error")

    def test_enrollment_requires_correct_bootstrap_token_and_returns_secret_once(self):
        client = self.make_client(
            enrollment_token="bootstrap-secret",
            credential_factory=lambda: "device-secret-001",
        )

        denied = self.enroll(client, token="wrong-token")
        self.assertEqual(denied.status_code, 403)

        enrolled = self.enroll(client)
        self.assertEqual(enrolled.status_code, 201)
        body = enrolled.get_json()
        self.assertEqual(body["status"], "enrolled")
        self.assertEqual(body["collector_id"], "collector-1")
        self.assertEqual(body["credential"], "device-secret-001")
        self.assertEqual(
            enrolled.headers["Cache-Control"],
            "no-store, max-age=0",
        )

        conn = self.connection_factory()
        try:
            row = conn.execute(
                """
                SELECT credential_fingerprint
                FROM collectors
                WHERE collector_id='collector-1'
                """
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(
            row[0],
            credential_fingerprint("device-secret-001"),
        )
        self.assertNotEqual(row[0], "device-secret-001")

        duplicate = self.enroll(client)
        self.assertEqual(duplicate.status_code, 409)

    def test_legacy_mode_preserves_s2_ingestion_without_credential(self):
        client = self.make_client(auth_required=False)

        response = client.post(
            "/api/collector/v1/batches",
            json=self.payload(),
            headers=self.batch_headers(),
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(self.batch_count(), 1)

    def test_authenticated_mode_rejects_missing_unknown_and_wrong_credentials(self):
        client = self.make_client(
            auth_required=True,
            enrollment_token="bootstrap-secret",
            credential_factory=lambda: "device-secret-001",
        )

        missing = client.post(
            "/api/collector/v1/batches",
            json=self.payload(),
            headers=self.batch_headers(),
        )
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(self.batch_count(), 0)

        unknown = client.post(
            "/api/collector/v1/batches",
            json=self.payload(),
            headers=self.batch_headers("device-secret-001"),
        )
        self.assertEqual(unknown.status_code, 401)
        self.assertEqual(self.batch_count(), 0)

        self.assertEqual(self.enroll(client).status_code, 201)

        wrong = client.post(
            "/api/collector/v1/batches",
            json=self.payload(),
            headers=self.batch_headers("wrong-secret"),
        )
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(self.batch_count(), 0)

    def test_valid_credential_persists_batch_and_updates_last_seen(self):
        client = self.make_client(
            auth_required=True,
            enrollment_token="bootstrap-secret",
            credential_factory=lambda: "device-secret-001",
        )
        self.assertEqual(self.enroll(client).status_code, 201)

        response = client.post(
            "/api/collector/v1/batches",
            json=self.payload(),
            headers=self.batch_headers("device-secret-001"),
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(self.batch_count(), 1)

        conn = self.connection_factory()
        try:
            row = conn.execute(
                """
                SELECT last_seen_at
                FROM collectors
                WHERE collector_id='collector-1'
                """
            ).fetchone()
        finally:
            conn.close()

        self.assertIsNotNone(row[0])

    def test_hostname_mismatch_fails_before_batch_persistence(self):
        client = self.make_client(
            auth_required=True,
            enrollment_token="bootstrap-secret",
            credential_factory=lambda: "device-secret-001",
        )
        self.assertEqual(self.enroll(client).status_code, 201)

        payload = self.payload()
        payload["hostname"] = "OTHER-HOST"
        response = client.post(
            "/api/collector/v1/batches",
            json=payload,
            headers=self.batch_headers("device-secret-001"),
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.batch_count(), 0)

    def test_revoked_collector_is_denied_before_batch_persistence(self):
        client = self.make_client(
            auth_required=True,
            enrollment_token="bootstrap-secret",
            credential_factory=lambda: "device-secret-001",
        )
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
            "/api/collector/v1/batches",
            json=self.payload(),
            headers=self.batch_headers("device-secret-001"),
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.batch_count(), 0)


if __name__ == "__main__":
    unittest.main()
