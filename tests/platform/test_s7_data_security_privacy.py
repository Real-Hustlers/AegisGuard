import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.platform.data_privacy import (
    DataSensitivity,
    REDACTED,
    classify_field,
    redact_sensitive_mapping,
    redact_sensitive_text,
)
from backend.storage.collector_ingest import (
    claim_next_collector_batch,
    mark_collector_batch_failed,
    mark_collector_batch_processed,
    persist_collector_batch,
)
from backend.storage.migrations import ensure_platform_schema


class S7DataSecurityPrivacyTests(unittest.TestCase):
    def test_field_classification_distinguishes_secrets_and_security_data(self):
        self.assertEqual(
            classify_field("access_token"),
            DataSensitivity.SECRET,
        )
        self.assertEqual(
            classify_field("raw_log"),
            DataSensitivity.SECURITY_SENSITIVE,
        )
        self.assertEqual(
            classify_field("source_ip"),
            DataSensitivity.SECURITY_SENSITIVE,
        )
        self.assertEqual(
            classify_field("severity"),
            DataSensitivity.PUBLIC,
        )
        self.assertEqual(
            classify_field("candidate_id"),
            DataSensitivity.INTERNAL,
        )

    def test_recursive_mapping_redacts_secrets_without_destroying_soc_data(self):
        value = {
            "username": "alice",
            "source_ip": "10.0.0.9",
            "authorization": "Bearer abc.def",
            "nested": {
                "api_key": "super-secret",
                "severity": "HIGH",
            },
        }

        safe = redact_sensitive_mapping(value)

        self.assertEqual(safe["username"], "alice")
        self.assertEqual(safe["source_ip"], "10.0.0.9")
        self.assertEqual(safe["authorization"], REDACTED)
        self.assertEqual(safe["nested"]["api_key"], REDACTED)
        self.assertEqual(safe["nested"]["severity"], "HIGH")

    def test_lower_trust_mapping_can_redact_security_identifiers(self):
        safe = redact_sensitive_mapping(
            {
                "username": "alice",
                "source_ip": "10.0.0.9",
                "severity": "HIGH",
            },
            redact_security_sensitive=True,
        )
        self.assertEqual(safe["username"], REDACTED)
        self.assertEqual(safe["source_ip"], REDACTED)
        self.assertEqual(safe["severity"], "HIGH")

    def test_sensitive_text_redaction_handles_common_secret_shapes(self):
        text = (
            "request failed authorization=abc123 "
            "api_key=qwerty Bearer live-token"
        )
        safe = redact_sensitive_text(text)

        self.assertNotIn("abc123", safe)
        self.assertNotIn("qwerty", safe)
        self.assertNotIn("live-token", safe)
        self.assertIn("authorization=[REDACTED]", safe)
        self.assertIn("api_key=[REDACTED]", safe)
        self.assertIn("Bearer [REDACTED]", safe)

    def test_failed_password_event_text_is_not_mistaken_for_a_secret(self):
        event = "Failed password for alice from 10.0.0.9 port 22 ssh2"
        self.assertEqual(redact_sensitive_text(event), event)


class S7DurableIngestPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "server.db"

    def tearDown(self):
        self.tmp.cleanup()

    def connection(self):
        conn = sqlite3.connect(str(self.db_path))
        ensure_platform_schema(conn)
        return conn

    def persist_and_claim(self, *, batch_id="batch-s7"):
        payload = {
            "batch_id": batch_id,
            "collector_id": "collector-s7",
            "hostname": "HOST-S7",
            "logs": [{
                "record_id": 101,
                "user": "alice",
                "source_ip": "10.0.0.9",
                "raw_log": "sensitive forensic event body",
            }],
        }
        conn = self.connection()
        try:
            inserted, _state = persist_collector_batch(
                conn,
                payload,
                peer_ip="10.0.0.2",
            )
            self.assertTrue(inserted)
            claimed = claim_next_collector_batch(conn)
            self.assertIsNotNone(claimed)
            return payload
        finally:
            conn.close()

    def read_queue_row(self, batch_id="batch-s7"):
        conn = self.connection()
        try:
            return conn.execute(
                """
                SELECT state, payload_json, last_error
                FROM collector_ingest_batches
                WHERE batch_id = ?
                """,
                (batch_id,),
            ).fetchone()
        finally:
            conn.close()

    def test_successful_batch_discards_duplicate_raw_payload(self):
        payload = self.persist_and_claim()
        before = self.read_queue_row()
        self.assertIn(payload["logs"][0]["raw_log"], before[1])

        conn = self.connection()
        try:
            self.assertTrue(
                mark_collector_batch_processed(conn, "batch-s7")
            )
        finally:
            conn.close()

        after = self.read_queue_row()
        self.assertEqual(after[0], "PROCESSED")
        self.assertEqual(after[1], "{}")
        self.assertIsNone(after[2])
        self.assertNotIn(
            payload["logs"][0]["raw_log"],
            after[1],
        )

    def test_failed_batch_retains_payload_but_redacts_error_secrets(self):
        payload = self.persist_and_claim(batch_id="batch-failed")

        conn = self.connection()
        try:
            self.assertTrue(
                mark_collector_batch_failed(
                    conn,
                    "batch-failed",
                    "transport error api_key=do-not-store",
                )
            )
        finally:
            conn.close()

        after = self.read_queue_row("batch-failed")
        self.assertEqual(after[0], "FAILED")
        self.assertIn(payload["logs"][0]["raw_log"], after[1])
        self.assertNotIn("do-not-store", after[2])
        self.assertIn("api_key=[REDACTED]", after[2])


if __name__ == "__main__":
    unittest.main()
