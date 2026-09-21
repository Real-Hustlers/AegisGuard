import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from flask import Flask

from backend.analyzer.collector_api import create_collector_blueprint
from backend.collector.state import CollectorState
from backend.collector.transport import (
    build_batch_payload,
    send_batch,
    validate_analyzer_url,
)
from backend.storage.migrations import ensure_platform_schema


class CollectorStateTests(unittest.TestCase):
    def test_spool_and_checkpoint_survive_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collector-state.db"
            state = CollectorState(path)
            collector_id = state.get_or_create_collector_id()
            payload = build_batch_payload(
                collector_id,
                "HOST01",
                "Windows",
                [{"record_id": 101, "event_type": "LOGON"}],
                batch_id="batch-1",
            )
            state.enqueue(payload, 101)

            reopened = CollectorState(path)
            self.assertEqual(reopened.get_or_create_collector_id(), collector_id)
            self.assertEqual(len(reopened.pending()), 1)
            self.assertIsNone(reopened.get_checkpoint())

            reopened.acknowledge("batch-1")

            final = CollectorState(path)
            self.assertEqual(final.pending(), [])
            self.assertEqual(final.get_checkpoint(), 101)


class TransportPolicyTests(unittest.TestCase):
    def test_remote_plain_http_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "requires HTTPS"):
            validate_analyzer_url("http://10.20.30.40:5000/api/collector/v1/batches")

    def test_loopback_http_and_remote_https_are_allowed(self):
        validate_analyzer_url("http://127.0.0.1:5000/api/collector/v1/batches")
        validate_analyzer_url("https://siem.example.test/api/collector/v1/batches")

    def test_send_batch_uses_tls_verification_and_identity_headers(self):
        session = Mock()
        session.post.return_value = Mock(status_code=202)
        payload = build_batch_payload(
            "collector-1",
            "HOST01",
            "Windows",
            [],
            batch_id="batch-1",
        )

        send_batch(
            "https://siem.example.test/api/collector/v1/batches",
            payload,
            ca_bundle="C:/AegisGuard/ca.pem",
            session=session,
        )

        _, kwargs = session.post.call_args
        self.assertEqual(kwargs["verify"], "C:/AegisGuard/ca.pem")
        self.assertEqual(
            kwargs["headers"]["X-AegisGuard-Collector-ID"],
            "collector-1",
        )
        self.assertEqual(
            kwargs["headers"]["X-AegisGuard-Batch-ID"],
            "batch-1",
        )


class CollectorIngestApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "server.db"

        def connection_factory():
            conn = sqlite3.connect(str(self.db_path))
            ensure_platform_schema(conn)
            return conn

        self.connection_factory = connection_factory
        app = Flask(__name__)
        app.register_blueprint(create_collector_blueprint(connection_factory))
        app.testing = True
        self.client = app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def _payload(self):
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

    def test_batch_is_durable_before_ack_and_duplicate_is_idempotent(self):
        payload = self._payload()
        headers = {
            "X-AegisGuard-Collector-ID": "collector-1",
            "X-AegisGuard-Batch-ID": "batch-1",
        }

        first = self.client.post(
            "/api/collector/v1/batches",
            json=payload,
            headers=headers,
        )
        self.assertEqual(first.status_code, 202)
        self.assertFalse(first.get_json()["duplicate"])
        self.assertEqual(first.get_json()["analysis_state"], "QUEUED")

        conn = self.connection_factory()
        try:
            row = conn.execute(
                """
                SELECT batch_id, collector_id, event_count, max_record_id, state
                FROM collector_ingest_batches
                WHERE batch_id='batch-1'
                """
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(row[0], "batch-1")
        self.assertEqual(row[1], "collector-1")
        self.assertEqual(row[2], 1)
        self.assertEqual(row[3], 101)
        self.assertEqual(row[4], "QUEUED")

        duplicate = self.client.post(
            "/api/collector/v1/batches",
            json=payload,
            headers=headers,
        )
        self.assertEqual(duplicate.status_code, 202)
        self.assertTrue(duplicate.get_json()["duplicate"])

        conn = self.connection_factory()
        try:
            count = conn.execute(
                "SELECT COUNT(*) FROM collector_ingest_batches"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 1)

    def test_identity_header_mismatch_is_rejected(self):
        response = self.client.post(
            "/api/collector/v1/batches",
            json=self._payload(),
            headers={
                "X-AegisGuard-Collector-ID": "different",
                "X-AegisGuard-Batch-ID": "batch-1",
            },
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
