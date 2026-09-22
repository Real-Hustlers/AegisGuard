import subprocess
import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import Mock, patch


sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import requests  # noqa: F401
except ModuleNotFoundError:
    requests_stub = ModuleType("requests")

    class RequestException(Exception):
        pass

    def _post(*args, **kwargs):
        raise RuntimeError("requests.post should be mocked in tests")

    requests_stub.RequestException = RequestException
    requests_stub.post = _post
    sys.modules["requests"] = requests_stub

import live_monitoring  # noqa: E402


class LiveMonitoringTests(unittest.TestCase):
    def test_send_log_uses_configured_analyzer_url(self):
        response = Mock(status_code=200, text="ok")

        with patch.object(live_monitoring.platform, "node", return_value="HOST01"), \
             patch.object(live_monitoring.platform, "platform", return_value="Windows-11"), \
             patch.object(live_monitoring.requests, "post", return_value=response) as mock_post:
            ok = live_monitoring.send_logs([{"event_type": "LOGON_SUCCESS"}])

        self.assertTrue(ok)
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], live_monitoring.ANALYZER)
        self.assertEqual(kwargs["json"]["machine_id"], "HOST01")
        self.assertEqual(kwargs["json"]["logs"][0]["event_type"], "LOGON_SUCCESS")
        self.assertEqual(kwargs["timeout"], live_monitoring.UPLOAD_TIMEOUT)

    def test_get_latest_record_id_returns_zero_on_bad_json(self):
        result = Mock(stdout="{not json}", stderr="", returncode=0)

        with patch.object(live_monitoring.subprocess, "run", return_value=result):
            record_id = live_monitoring.get_latest_record_id()

        self.assertEqual(record_id, 0)

    def test_security_log_permission_error_is_actionable(self):
        result = Mock(stdout="", stderr="Attempted to perform an unauthorized operation.", returncode=1)

        with patch.object(live_monitoring.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(PermissionError, "Administrator privileges"):
                live_monitoring.get_latest_record_id()

    def test_collect_new_events_parses_single_record(self):
        result = Mock(
            stdout='{"RecordId": 101, "Id": 4624, "Message": "demo"}',
            stderr="",
            returncode=0,
        )

        with patch.object(
            live_monitoring,
            "_run_powershell",
            return_value=result,
        ) as mock_run:
            events = live_monitoring.collect_new_events(100)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["RecordId"], 101)
        self.assertEqual(events[0]["Id"], 4624)
        command = mock_run.call_args.args[0]
        self.assertIn("EventRecordID > 100", command)
        self.assertIn("-Oldest", command)
        self.assertIn("-MaxEvents 100", command)

    def test_collect_new_events_returns_empty_list_on_timeout(self):
        with patch.object(
            live_monitoring.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=30),
        ):
            events = live_monitoring.collect_new_events(100)

        self.assertEqual(events, [])

    def test_start_live_monitor_spools_before_advancing_collection_cursor(self):
        event = {
            "RecordId": 101,
            "Id": 4624,
            "Message": "demo",
            "TimeCreated": "2026-08-18T10:00:00Z",
        }
        parsed = {
            "event_type": "LOGON_SUCCESS",
            "user": "alice",
            "hostname": "HOST01",
            "source_ip": "",
            "destination_ip": "",
            "process": "",
            "file_path": "",
        }
        runtime = Mock()
        runtime.analyzer_url = "https://siem.example.test/api/collector/v1/batches"
        runtime.collector_id = "collector-1"
        runtime.state.path = Path("collector_state.db")
        runtime.initialize.return_value = 100
        runtime.enqueue_logs.return_value = "batch-1"
        runtime.flush_pending.return_value = True
        runtime.collection_cursor.return_value = 101
        runtime.checkpoint.return_value = 101

        with patch.object(live_monitoring, "collect_new_events", side_effect=[[event], KeyboardInterrupt()]) as mock_collect, \
             patch.object(live_monitoring, "parse_event", return_value=parsed), \
             patch.object(live_monitoring, "detect_threat", return_value="LOW"), \
             patch.object(live_monitoring.time, "sleep", return_value=None):
            with self.assertRaises(KeyboardInterrupt):
                live_monitoring.start_live_monitor(
                    last_record=100,
                    runtime=runtime,
                )

        self.assertEqual(mock_collect.call_args_list[0].args[0], 100)
        self.assertEqual(mock_collect.call_args_list[1].args[0], 101)
        sent_batch = runtime.enqueue_logs.call_args.args[0]
        self.assertEqual(sent_batch[0]["record_id"], 101)
        self.assertEqual(sent_batch[0]["threat_level"], "LOW")
        runtime.flush_pending.assert_called_once()

    def test_heartbeat_scheduler_honors_interval(self):
        runtime = Mock()
        runtime.auth_required = True
        runtime.heartbeat_url = (
            "https://siem.example.test/api/collector/v1/heartbeat"
        )
        runtime.collector_id = "collector-1"
        runtime.heartbeat.return_value = {
            "status": "alive",
            "collector_id": "collector-1",
            "last_heartbeat_at": "2026-09-22 12:30:00",
        }

        next_due, sent = live_monitoring.maybe_send_heartbeat(
            runtime,
            0.0,
            30.0,
            now=100.0,
        )
        self.assertTrue(sent)
        self.assertEqual(next_due, 130.0)
        runtime.heartbeat.assert_called_once()

        next_due, sent = live_monitoring.maybe_send_heartbeat(
            runtime,
            next_due,
            30.0,
            now=120.0,
        )
        self.assertFalse(sent)
        self.assertEqual(next_due, 130.0)
        runtime.heartbeat.assert_called_once()

        next_due, sent = live_monitoring.maybe_send_heartbeat(
            runtime,
            next_due,
            30.0,
            now=131.0,
        )
        self.assertTrue(sent)
        self.assertEqual(next_due, 161.0)
        self.assertEqual(runtime.heartbeat.call_count, 2)

    def test_heartbeat_network_failure_does_not_stop_collection_loop(self):
        runtime = Mock()
        runtime.analyzer_url = (
            "https://siem.example.test/api/collector/v1/batches"
        )
        runtime.heartbeat_url = (
            "https://siem.example.test/api/collector/v1/heartbeat"
        )
        runtime.auth_required = True
        runtime.collector_id = "collector-1"
        runtime.state.path = Path("collector_state.db")
        runtime.initialize.return_value = 100
        runtime.collection_cursor.return_value = 100
        runtime.checkpoint.return_value = 100
        runtime.flush_pending.return_value = True
        runtime.heartbeat.side_effect = (
            live_monitoring.requests.ConnectionError("offline")
        )

        with patch.object(
            live_monitoring,
            "collect_new_events",
            side_effect=[[], KeyboardInterrupt()],
        ) as mock_collect, patch.object(
            live_monitoring.time,
            "monotonic",
            return_value=100.0,
        ), patch.object(
            live_monitoring.time,
            "sleep",
            return_value=None,
        ):
            with self.assertRaises(KeyboardInterrupt):
                live_monitoring.start_live_monitor(
                    last_record=100,
                    runtime=runtime,
                )

        self.assertEqual(mock_collect.call_count, 2)
        runtime.flush_pending.assert_called_once()
        runtime.heartbeat.assert_called_once()
        self.assertEqual(runtime.collection_cursor.call_count, 1)


if __name__ == "__main__":
    unittest.main()
