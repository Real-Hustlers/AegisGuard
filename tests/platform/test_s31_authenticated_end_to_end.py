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
from backend.analyzer.ingest_pipeline import (
    IngestDependencies,
    process_collector_payload,
)
from backend.analyzer.ingest_worker import CollectorIngestWorker
from backend.collector.durable_runtime import DurableCollectorRuntime
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


class _ResponseAdapter:
    def __init__(self, response):
        self._response = response
        self.status_code = response.status_code

    def json(self):
        return self._response.get_json()


class _FakeConnection:
    def close(self):
        pass


class _AnalyzerHarness:
    def __init__(self):
        self.stored = set()
        self.classified_batches = []
        self.inserted_batches = []
        self.incident_calls = []

        self.dependencies = IngestDependencies(
            build_log_identity=self.identity,
            get_existing_log_ids=self.existing,
            classify_records=self.classify,
            insert_new_security_logs=self.insert,
            record_collector_endpoint=lambda *_args: None,
            get_connection=lambda: _FakeConnection(),
            scan_and_generate_incidents=self.scan_incidents,
        )

    @staticmethod
    def identity(log):
        return (
            f"windows:{str(log['hostname']).lower()}:"
            f"{int(log['record_id'])}"
        )

    def existing(self, logs):
        return {
            self.identity(log)
            for log in logs
            if self.identity(log) in self.stored
        }

    def classify(self, logs):
        batch = [dict(log) for log in logs]
        self.classified_batches.append(batch)
        for log in batch:
            log["ml_prediction"] = "TEST_DETECTION"
        return batch

    def insert(self, logs):
        batch = [dict(log) for log in logs]
        self.inserted_batches.append(batch)

        inserted = []
        for log in batch:
            log_id = self.identity(log)
            if log_id in self.stored:
                continue
            self.stored.add(log_id)
            item = dict(log)
            item["log_id"] = log_id
            inserted.append(item)
        return inserted

    def scan_incidents(self, conn):
        self.incident_calls.append(conn)
        return 1


class S31AuthenticatedCollectorEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.server_db = root / "server.db"
        self.collector_db = root / "collector-state.db"
        self.enrollment_calls = 0

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
            )
        )
        app.testing = True
        self.client = app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def event(record_id):
        return {
            "record_id": int(record_id),
            "event_type": "FAILED_LOGIN",
            "user": "alice",
            "source_ip": "10.10.10.8",
            "destination_ip": "10.10.10.20",
            "severity": "HIGH",
            "raw_log": f"failed login record {record_id}",
        }

    def enrollment_sender(
        self,
        _url,
        payload,
        bootstrap_token,
        **_kwargs,
    ):
        self.enrollment_calls += 1
        response = self.client.post(
            "/api/collector/v1/enroll",
            json=payload,
            headers={
                ENROLLMENT_TOKEN_HEADER: bootstrap_token,
            },
        )
        return _ResponseAdapter(response)

    def batch_sender(
        self,
        _url,
        payload,
        *,
        credential=None,
        **_kwargs,
    ):
        headers = {
            "X-AegisGuard-Collector-ID": payload["collector_id"],
            "X-AegisGuard-Batch-ID": payload["batch_id"],
        }
        if credential:
            headers[COLLECTOR_CREDENTIAL_HEADER] = credential

        response = self.client.post(
            "/api/collector/v1/batches",
            json=payload,
            headers=headers,
        )
        return _ResponseAdapter(response)

    def make_runtime(
        self,
        state,
        *,
        enrollment_token,
    ):
        return DurableCollectorRuntime(
            state,
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            enrollment_url=(
                "https://siem.example.test/api/collector/v1/enroll"
            ),
            enrollment_token=enrollment_token,
            auth_required=True,
            collector_version="0.1.0",
            sender=self.batch_sender,
            enrollment_sender=self.enrollment_sender,
            retry_base_seconds=2,
            retry_max_seconds=8,
            retry_jitter_ratio=0,
        )

    def server_batch(self, batch_id):
        conn = self.connection_factory()
        try:
            return conn.execute(
                """
                SELECT batch_id, collector_id, hostname, state, event_count,
                       max_record_id
                FROM collector_ingest_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()
        finally:
            conn.close()

    def test_enroll_deliver_restart_reuse_and_revocation_fail_closed(self):
        collector_state = CollectorState(self.collector_db, credential_protector=_TestProtector())
        collector_state.initialize_checkpoint(100)

        runtime = self.make_runtime(
            collector_state,
            enrollment_token="bootstrap-secret",
        )

        # 1. First delivery must enroll, persist the credential locally,
        # authenticate the batch, and only then advance the ACK checkpoint.
        first_batch = runtime.enqueue_logs(
            [self.event(101)],
            [101],
        )

        self.assertEqual(collector_state.get_checkpoint(), 100)
        self.assertEqual(len(collector_state.pending()), 1)
        self.assertTrue(runtime.flush_pending())

        self.assertEqual(self.enrollment_calls, 1)
        self.assertEqual(
            collector_state.get_collector_credential(),
            "device-secret-001",
        )
        self.assertEqual(collector_state.get_checkpoint(), 101)
        self.assertEqual(collector_state.pending(), [])

        conn = self.connection_factory()
        try:
            collector_row = conn.execute(
                """
                SELECT collector_id, hostname, status,
                       credential_fingerprint, last_seen_at, revoked_at
                FROM collectors
                WHERE collector_id = ?
                """,
                (runtime.collector_id,),
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(collector_row[0], runtime.collector_id)
        self.assertEqual(collector_row[1], "HOST01")
        self.assertEqual(collector_row[2], "ENROLLED")
        self.assertEqual(
            collector_row[3],
            credential_fingerprint("device-secret-001"),
        )
        self.assertNotEqual(collector_row[3], "device-secret-001")
        self.assertIsNotNone(collector_row[4])
        self.assertIsNone(collector_row[5])

        first_server_batch = self.server_batch(first_batch)
        self.assertEqual(first_server_batch[1], runtime.collector_id)
        self.assertEqual(first_server_batch[2], "HOST01")
        self.assertEqual(first_server_batch[3], "QUEUED")
        self.assertEqual(first_server_batch[4], 1)
        self.assertEqual(first_server_batch[5], 101)

        # 2. The existing async worker path must process the authenticated
        # durable batch without changing authentication semantics.
        analyzer = _AnalyzerHarness()

        def processor(payload, peer_ip):
            return process_collector_payload(
                payload,
                peer_ip,
                dependencies=analyzer.dependencies,
            )

        worker = CollectorIngestWorker(
            self.connection_factory,
            processor,
        )
        result = worker.run_once()

        self.assertEqual(result["batch_id"], first_batch)
        self.assertEqual(result["state"], "PROCESSED")
        self.assertEqual(result["result"]["new_logs_added"], 1)
        self.assertEqual(result["result"]["incidents_created"], 1)
        self.assertEqual(len(analyzer.stored), 1)
        self.assertEqual(len(analyzer.incident_calls), 1)

        # 3. A restart must reuse the durable credential and must not require
        # or repeat bootstrap enrollment.
        restarted_state = CollectorState(self.collector_db, credential_protector=_TestProtector())
        restarted = self.make_runtime(
            restarted_state,
            enrollment_token=None,
        )

        self.assertEqual(restarted.collector_id, runtime.collector_id)
        self.assertEqual(
            restarted_state.get_collector_credential(),
            "device-secret-001",
        )

        second_batch = restarted.enqueue_logs(
            [self.event(102)],
            [102],
        )
        self.assertTrue(restarted.flush_pending())

        self.assertEqual(self.enrollment_calls, 1)
        self.assertEqual(restarted_state.get_checkpoint(), 102)
        self.assertEqual(self.server_batch(second_batch)[3], "QUEUED")

        # 4. Revocation must fail closed. The already-issued credential remains
        # present locally, but the server rejects it before queue persistence.
        conn = self.connection_factory()
        try:
            self.assertTrue(
                revoke_collector(
                    conn,
                    runtime.collector_id,
                    revoked_at="2026-09-22T13:00:00Z",
                )
            )
        finally:
            conn.close()

        third_batch = restarted.enqueue_logs(
            [self.event(103)],
            [103],
        )

        self.assertFalse(restarted.flush_pending())
        self.assertEqual(restarted_state.get_checkpoint(), 102)

        pending = restarted_state.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["batch_id"], third_batch)
        self.assertEqual(pending[0]["attempts"], 1)
        self.assertIn(
            "durable collector ACK requires HTTP 202; got 403",
            pending[0]["last_error"],
        )

        self.assertIsNone(self.server_batch(third_batch))

        conn = self.connection_factory()
        try:
            revoked_row = conn.execute(
                """
                SELECT status, revoked_at
                FROM collectors
                WHERE collector_id = ?
                """,
                (runtime.collector_id,),
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(revoked_row[0], "REVOKED")
        self.assertEqual(revoked_row[1], "2026-09-22T13:00:00Z")


if __name__ == "__main__":
    unittest.main()
