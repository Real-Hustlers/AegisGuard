import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.analyzer.ingest_worker import CollectorIngestWorker
from backend.storage.collector_ingest import (
    claim_next_collector_batch,
    mark_collector_batch_failed,
    mark_collector_batch_processed,
    persist_collector_batch,
)
from backend.storage.migrations import ensure_platform_schema


class DurableIngestWorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "server.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection_factory(self):
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        ensure_platform_schema(conn)
        return conn

    def persist(self, batch_id="batch-1"):
        payload = {
            "batch_id": batch_id,
            "collector_id": "collector-1",
            "hostname": "HOST01",
            "os": "Windows",
            "logs": [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
        }
        conn = self.connection_factory()
        try:
            inserted, state = persist_collector_batch(
                conn, payload, peer_ip="10.20.30.40"
            )
        finally:
            conn.close()
        self.assertTrue(inserted)
        self.assertEqual(state, "QUEUED")
        return payload

    def row(self, batch_id="batch-1"):
        conn = self.connection_factory()
        try:
            return conn.execute(
                """
                SELECT state, attempts, processed_at, last_error
                FROM collector_ingest_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()
        finally:
            conn.close()

    def test_claim_is_atomic_and_increments_attempt_once(self):
        self.persist()
        conn = self.connection_factory()
        try:
            claimed = claim_next_collector_batch(conn)
        finally:
            conn.close()
        self.assertEqual(claimed["batch_id"], "batch-1")
        self.assertEqual(claimed["attempts"], 1)
        self.assertEqual(claimed["peer_ip"], "10.20.30.40")

        conn = self.connection_factory()
        try:
            self.assertIsNone(claim_next_collector_batch(conn))
        finally:
            conn.close()
        row = self.row()
        self.assertEqual(row[0], "PROCESSING")
        self.assertEqual(row[1], 1)

    def test_processed_transition_records_processed_timestamp(self):
        self.persist()
        conn = self.connection_factory()
        try:
            claim_next_collector_batch(conn)
        finally:
            conn.close()
        conn = self.connection_factory()
        try:
            self.assertTrue(mark_collector_batch_processed(conn, "batch-1"))
        finally:
            conn.close()
        row = self.row()
        self.assertEqual(row[0], "PROCESSED")
        self.assertEqual(row[1], 1)
        self.assertIsNotNone(row[2])
        self.assertIsNone(row[3])

    def test_failed_transition_preserves_error(self):
        self.persist()
        conn = self.connection_factory()
        try:
            claim_next_collector_batch(conn)
        finally:
            conn.close()
        conn = self.connection_factory()
        try:
            self.assertTrue(
                mark_collector_batch_failed(conn, "batch-1", "classifier unavailable")
            )
        finally:
            conn.close()
        row = self.row()
        self.assertEqual(row[0], "FAILED")
        self.assertEqual(row[1], 1)
        self.assertIsNone(row[2])
        self.assertEqual(row[3], "classifier unavailable")

    def test_worker_marks_successful_batch_processed(self):
        payload = self.persist()
        calls = []

        def processor(received_payload, peer_ip):
            calls.append((received_payload, peer_ip))
            return {"new_logs_added": 1}

        worker = CollectorIngestWorker(self.connection_factory, processor)
        result = worker.run_once()
        self.assertEqual(result["state"], "PROCESSED")
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(result["result"]["new_logs_added"], 1)
        self.assertEqual(calls, [(payload, "10.20.30.40")])
        self.assertEqual(self.row()[0], "PROCESSED")
        self.assertIsNone(worker.run_once())

    def test_worker_marks_processing_exception_failed(self):
        self.persist()

        def processor(_payload, _peer_ip):
            raise RuntimeError("pipeline exploded")

        worker = CollectorIngestWorker(self.connection_factory, processor)
        result = worker.run_once()
        self.assertEqual(result["state"], "FAILED")
        self.assertEqual(result["attempts"], 1)
        self.assertEqual(result["error"], "pipeline exploded")
        row = self.row()
        self.assertEqual(row[0], "FAILED")
        self.assertEqual(row[3], "pipeline exploded")


if __name__ == "__main__":
    unittest.main()
