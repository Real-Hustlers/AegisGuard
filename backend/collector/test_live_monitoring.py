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
            ok = live_monitoring.send_log({"event_type": "LOGON_SUCCESS"})

        self.assertTrue(ok)
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], live_monitoring.ANALYZER)
        self.assertEqual(kwargs["json"]["machine_id"], "HOST01")
        self.assertEqual(kwargs["json"]["logs"][0]["event_type"], "LOGON_SUCCESS")
        self.assertEqual(kwargs["timeout"], 5)

    def test_get_latest_record_id_returns_zero_on_bad_json(self):
        result = Mock(stdout="{not json}", stderr="", returncode=0)

        with patch.object(live_monitoring.subprocess, "run", return_value=result):
            record_id = live_monitoring.get_latest_record_id()

        self.assertEqual(record_id, 0)

    def test_collect_new_events_parses_single_record(self):
        result = Mock(
            stdout='{"RecordId": 101, "Id": 4624, "Message": "demo"}',
            stderr="",
            returncode=0,
        )

        with patch.object(live_monitoring.subprocess, "run", return_value=result):
            events = live_monitoring.collect_new_events(100)

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["RecordId"], 101)
        self.assertEqual(events[0]["Id"], 4624)

    def test_collect_new_events_returns_empty_list_on_timeout(self):
        with patch.object(
            live_monitoring.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell", timeout=30),
        ):
            events = live_monitoring.collect_new_events(100)

        self.assertEqual(events, [])

    def test_start_live_monitor_advances_last_record(self):
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

        with patch.object(live_monitoring, "collect_new_events", side_effect=[[event], KeyboardInterrupt()]) as mock_collect, \
             patch.object(live_monitoring, "parse_event", return_value=parsed), \
             patch.object(live_monitoring, "detect_threat", return_value="LOW"), \
             patch.object(live_monitoring, "send_log") as mock_send, \
             patch.object(live_monitoring.time, "sleep", return_value=None):
            with self.assertRaises(KeyboardInterrupt):
                live_monitoring.start_live_monitor(last_record=100)

        self.assertEqual(mock_collect.call_args_list[0].args[0], 100)
        self.assertEqual(mock_collect.call_args_list[1].args[0], 101)
        sent_payload = mock_send.call_args.args[0]
        self.assertEqual(sent_payload["record_id"], 101)
        self.assertEqual(sent_payload["threat_level"], "LOW")


if __name__ == "__main__":
    unittest.main()
