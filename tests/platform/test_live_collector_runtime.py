import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import requests

from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.state import CollectorState


class _Clock:
    def __init__(self, value=1000.0):
        self.value = float(value)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += float(seconds)


class DurableCollectorRuntimeTests(unittest.TestCase):
    def make_runtime(self, tmp, sender, clock=None):
        state = CollectorState(Path(tmp) / "collector-state.db")
        state.initialize_checkpoint(100)
        clock = clock or _Clock()
        runtime = DurableCollectorRuntime(
            state,
            "https://siem.example.test/api/collector/v1/batches",
            hostname="HOST01",
            os_name="Windows-11",
            sender=sender,
            retry_base_seconds=2,
            retry_max_seconds=8,
            retry_jitter_ratio=0,
            clock=clock,
        )
        return state, runtime, clock

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

            state, runtime, clock = self.make_runtime(tmp, sender)
            batch_id = runtime.enqueue_logs(
                [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                [101],
            )

            self.assertFalse(runtime.flush_pending())
            self.assertEqual(state.get_checkpoint(), 100)
            pending = state.pending()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["attempts"], 1)
            self.assertEqual(pending[0]["next_attempt_at"], 1002.0)

            # Backoff must not generate another network attempt.
            self.assertFalse(runtime.flush_pending())
            self.assertEqual(len(payloads), 1)

            clock.advance(2)
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

            state, runtime, _clock = self.make_runtime(tmp, sender)
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

            state, runtime, _clock = self.make_runtime(tmp, sender)

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

    def test_backoff_schedule_survives_runtime_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = _Clock(2000)

            def offline(_url, _payload, **_kwargs):
                raise requests.RequestException("offline")

            state, runtime, _ = self.make_runtime(tmp, offline, clock=clock)
            runtime.enqueue_logs(
                [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                [101],
            )
            self.assertFalse(runtime.flush_pending())

            accepted_calls = []

            def accepted(_url, payload, **_kwargs):
                accepted_calls.append(payload["batch_id"])
                return self.accepted_response(payload)

            reopened_state = CollectorState(Path(tmp) / "collector-state.db")
            restarted = DurableCollectorRuntime(
                reopened_state,
                "https://siem.example.test/api/collector/v1/batches",
                hostname="HOST01",
                os_name="Windows-11",
                sender=accepted,
                retry_base_seconds=2,
                retry_max_seconds=8,
                retry_jitter_ratio=0,
                clock=clock,
            )

            clock.advance(1)
            self.assertFalse(restarted.flush_pending())
            self.assertEqual(accepted_calls, [])

            clock.advance(1)
            self.assertTrue(restarted.flush_pending())
            self.assertEqual(len(accepted_calls), 1)
            self.assertEqual(reopened_state.get_checkpoint(), 101)

    def test_exponential_backoff_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            state, runtime, _clock = self.make_runtime(
                tmp,
                lambda *_args, **_kwargs: None,
            )
            self.assertEqual(runtime.retry_delay_seconds("batch-1", 1), 2.0)
            self.assertEqual(runtime.retry_delay_seconds("batch-1", 2), 4.0)
            self.assertEqual(runtime.retry_delay_seconds("batch-1", 3), 8.0)
            self.assertEqual(runtime.retry_delay_seconds("batch-1", 4), 8.0)
            self.assertEqual(state.get_checkpoint(), 100)

    def test_health_snapshot_tracks_backlog_retry_and_last_ack(self):
        with tempfile.TemporaryDirectory() as tmp:
            clock = _Clock(3000)

            def offline(_url, _payload, **_kwargs):
                raise requests.RequestException("offline")

            state, runtime, _ = self.make_runtime(tmp, offline, clock=clock)
            runtime.enqueue_logs(
                [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                [101],
            )

            before = runtime.health_snapshot()
            self.assertEqual(before["status"], "BACKLOG")
            self.assertEqual(before["pending_batches"], 1)
            self.assertEqual(before["checkpoint"], 100)
            self.assertEqual(before["collection_cursor"], 101)
            self.assertIsNone(before["last_successful_ack_at"])

            self.assertFalse(runtime.flush_pending())
            failed = runtime.health_snapshot()
            self.assertEqual(failed["status"], "RETRY_WAIT")
            self.assertEqual(failed["oldest_pending_attempts"], 1)
            self.assertEqual(failed["retry_in_seconds"], 2.0)
            self.assertIn("offline", failed["last_error"])

            runtime.sender = lambda _url, payload, **_kwargs: (
                self.accepted_response(payload)
            )
            clock.advance(2)
            self.assertTrue(runtime.flush_pending())

            healthy = runtime.health_snapshot()
            self.assertEqual(healthy["status"], "HEALTHY")
            self.assertEqual(healthy["pending_batches"], 0)
            self.assertEqual(healthy["checkpoint"], 101)
            self.assertEqual(healthy["collection_cursor"], 101)
            self.assertEqual(healthy["last_successful_ack_at"], 3002.0)


if __name__ == "__main__":
    unittest.main()
