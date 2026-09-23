import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.collector.state import CollectorState
from backend.platform.sqlite_security import configure_sqlite_data_security
from backend.storage.collector_ingest import (
    DEFAULT_FAILED_PAYLOAD_RETENTION_DAYS,
    claim_next_collector_batch,
    mark_collector_batch_failed,
    persist_collector_batch,
    scrub_expired_failed_payloads,
)
from backend.storage.migrations import ensure_platform_schema


class S7BSQLiteSecurityTests(unittest.TestCase):
    def test_sqlite_security_pragmas_are_enabled(self):
        conn = sqlite3.connect(":memory:")
        try:
            snapshot = configure_sqlite_data_security(conn)
            self.assertTrue(snapshot["secure_delete"])
            self.assertTrue(snapshot["temp_store_memory"])
            self.assertEqual(conn.execute("PRAGMA secure_delete").fetchone()[0], 1)
            self.assertEqual(conn.execute("PRAGMA temp_store").fetchone()[0], 2)
        finally:
            conn.close()

    def test_collector_state_connections_use_secure_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = CollectorState(Path(tmp) / "collector_state.db")
            conn = state._connect()
            try:
                self.assertEqual(conn.execute("PRAGMA secure_delete").fetchone()[0], 1)
                self.assertEqual(conn.execute("PRAGMA temp_store").fetchone()[0], 2)
            finally:
                conn.close()


class S7BFailedPayloadRetentionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "server.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection(self):
        conn = sqlite3.connect(str(self.db_path))
        ensure_platform_schema(conn)
        configure_sqlite_data_security(conn)
        return conn

    def make_failed_batch(self, batch_id, received_at):
        payload = {
            "batch_id": batch_id,
            "collector_id": "collector-s7b",
            "hostname": "HOST-S7B",
            "logs": [{
                "record_id": 77,
                "user": "alice",
                "raw_log": f"sensitive payload {batch_id}",
            }],
        }

        conn = self.connection()
        try:
            inserted, _state = persist_collector_batch(
                conn,
                payload,
                peer_ip="10.0.0.8",
            )
            self.assertTrue(inserted)
            claimed = claim_next_collector_batch(conn)
            self.assertIsNotNone(claimed)
            self.assertTrue(
                mark_collector_batch_failed(
                    conn,
                    batch_id,
                    "pipeline failed",
                )
            )
            conn.execute(
                """
                UPDATE collector_ingest_batches
                SET received_at = ?
                WHERE batch_id = ?
                """,
                (received_at, batch_id),
            )
            conn.commit()
        finally:
            conn.close()

        return payload

    def row(self, batch_id):
        conn = self.connection()
        try:
            return conn.execute(
                """
                SELECT state, payload_json, last_error, received_at
                FROM collector_ingest_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()
        finally:
            conn.close()

    def test_expired_failed_payload_is_scrubbed_but_metadata_remains(self):
        now = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)
        old = (
            now - timedelta(days=DEFAULT_FAILED_PAYLOAD_RETENTION_DAYS + 1)
        ).strftime("%Y-%m-%d %H:%M:%S")

        payload = self.make_failed_batch("old-failed", old)

        conn = self.connection()
        try:
            scrubbed = scrub_expired_failed_payloads(conn, now=now)
        finally:
            conn.close()

        self.assertEqual(scrubbed, 1)
        row = self.row("old-failed")
        self.assertEqual(row[0], "FAILED")
        self.assertEqual(row[1], "{}")
        self.assertEqual(row[2], "pipeline failed")
        self.assertNotIn(payload["logs"][0]["raw_log"], row[1])

    def test_recent_failed_payload_remains_available_for_recovery(self):
        now = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)
        recent = (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")

        payload = self.make_failed_batch("recent-failed", recent)

        conn = self.connection()
        try:
            scrubbed = scrub_expired_failed_payloads(conn, now=now)
        finally:
            conn.close()

        self.assertEqual(scrubbed, 0)
        row = self.row("recent-failed")
        stored = json.loads(row[1])
        self.assertEqual(
            stored["logs"][0]["raw_log"],
            payload["logs"][0]["raw_log"],
        )

    def test_retention_days_are_bounded(self):
        conn = self.connection()
        try:
            with self.assertRaises(ValueError):
                scrub_expired_failed_payloads(conn, retention_days=0)
            with self.assertRaises(ValueError):
                scrub_expired_failed_payloads(conn, retention_days=366)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
