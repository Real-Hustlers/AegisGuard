import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import requests

from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.state import CollectorState


class DurableCollectorRuntimeTests(unittest.TestCase):
    def make_runtime(self, tmp, sender):
        state = CollectorState(Path(tmp) / "collector-state.db")
        state.initialize_checkpoint(100)
        runtime = DurableCollectorRuntime(
            state,
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            sender=sender,
        )
        return state, runtime

    @staticmethod
    def accepted_response(payload):
        response = Mock(status_code=202)
        response.json.return_value = {
            "status": "accepted",
            "collector_id": payload["collector_id"],
            "batch_id": payload["batch_id"],
            "duplicate": False,
            "analysis_state": "QUEUED",
        }
        return response

    def test_retry_reuses_stable_batch_id_and_ack_advances_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            payloads = []

            def sender(_url, payload, **_kwargs):
                payloads.append(dict(payload))
                if len(payloads) == 1:
                    raise requests.RequestException("offline")
                return self.accepted_response(payload)

            state, runtime = self.make_runtime(tmp, sender)
            batch_id = runtime.enqueue_logs(
                [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                [101],
            )

            self.assertFalse(runtime.flush_pending())
            self.assertEqual(state.get_checkpoint(), 100)
            self.assertEqual(len(state.pending()), 1)
            self.assertEqual(state.pending()[0]["attempts"], 1)

            self.assertTrue(runtime.flush_pending())
            self.assertEqual(state.get_checkpoint(), 101)
            self.assertEqual(state.pending(), [])
            self.assertEqual(payloads[0]["batch_id"], batch_id)
            self.assertEqual(payloads[1]["batch_id"], batch_id)

    def test_mismatched_ack_never_advances_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            def sender(_url, payload, **_kwargs):
                response = self.accepted_response(payload)
                response.json.return_value["batch_id"] = "wrong-batch"
                return response

            state, runtime = self.make_runtime(tmp, sender)
            runtime.enqueue_logs(
                [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                [101],
            )

            self.assertFalse(runtime.flush_pending())
            self.assertEqual(state.get_checkpoint(), 100)
            pending = state.pending()
            self.assertEqual(len(pending), 1)
            self.assertIn("batch_id mismatch", pending[0]["last_error"])

    def test_fifo_failure_blocks_later_batch_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            attempted_record_ids = []

            def sender(_url, payload, **_kwargs):
                attempted_record_ids.append(payload["logs"][0]["record_id"])
                raise requests.RequestException("offline")

            state, runtime = self.make_runtime(tmp, sender)

            runtime.enqueue_logs(
                [{"record_id": 102, "event_type": "LOGON_SUCCESS"}],
                [102],
            )
            runtime.enqueue_logs(
                [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                [101],
            )

            self.assertFalse(runtime.flush_pending(limit=1))
            self.assertEqual(attempted_record_ids, [101])
            self.assertEqual(state.get_checkpoint(), 100)
            self.assertEqual(len(state.pending()), 2)


if __name__ == "__main__":
    unittest.main()
