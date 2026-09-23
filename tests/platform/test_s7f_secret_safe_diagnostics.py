import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from backend.collector import collector
from backend.collector import live_monitoring
from backend.collector import main as collector_main
from backend.collector.diagnostics import (
    sanitize_diagnostic,
    sanitize_http_response,
    sanitize_url_for_diagnostics,
)
from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.state import CollectorState


class S7FSecretSafeDiagnosticsTests(unittest.TestCase):
    def test_structured_diagnostic_redacts_secret_but_preserves_soc_message(self):
        safe = sanitize_diagnostic({
            "status": "error",
            "credential": "device-secret-001",
            "message": "Failed password for alice from 10.0.0.8",
        })

        self.assertNotIn("device-secret-001", safe)
        self.assertIn("[REDACTED]", safe)
        self.assertIn("Failed password for alice", safe)

    def test_http_response_json_is_secret_safe(self):
        response = Mock()
        response.json.return_value = {
            "status": "rejected",
            "access_token": "token-123",
        }
        response.text = '{"access_token":"token-123"}'

        safe = sanitize_http_response(response)

        self.assertNotIn("token-123", safe)
        self.assertIn("[REDACTED]", safe)
        self.assertIn("rejected", safe)

    def test_diagnostic_url_drops_userinfo_query_and_fragment(self):
        safe = sanitize_url_for_diagnostics(
            "https://alice:secret@example.test:8443/api?"
            "access_token=token-123#fragment"
        )

        self.assertEqual(
            safe,
            "https://example.test:8443/api",
        )

    def test_legacy_main_uses_governed_raw_output_policy(self):
        raw_logs = [{"RecordId": 101, "Message": "security event"}]

        with patch.object(
            collector_main,
            "collect_security_logs",
            return_value=raw_logs,
        ), patch.object(
            collector_main,
            "save_raw_logs",
        ) as save_raw, patch.object(
            collector_main,
            "parse_event",
            return_value={"event_type": "LOGON_SUCCESS"},
        ), patch.object(
            collector_main,
            "detect_threat",
            return_value="LOW",
        ), patch.object(
            collector_main,
            "send_logs",
            return_value=True,
        ), patch.object(
            collector_main,
            "start_live_monitor",
        ) as start_live, redirect_stdout(io.StringIO()):
            collector_main.main()

        save_raw.assert_called_once_with(raw_logs)
        start_live.assert_called_once_with(101)

    def test_legacy_upload_response_does_not_print_secret(self):
        response = Mock(
            status_code=200,
            text='{"credential":"server-secret"}',
        )
        response.json.return_value = {
            "status": "success",
            "credential": "server-secret",
        }

        output = io.StringIO()
        with patch.object(
            collector.requests,
            "post",
            return_value=response,
        ), redirect_stdout(output):
            self.assertTrue(
                collector.send_logs(
                    [{"event_type": "LOGON_SUCCESS"}]
                )
            )

        text = output.getvalue()
        self.assertNotIn("server-secret", text)
        self.assertIn("[REDACTED]", text)

    def test_live_json_parse_failure_omits_raw_security_event(self):
        secret_event = "RAW-EVENT-CONTENT-SHOULD-NOT-PRINT"
        result = Mock(
            stdout='{"Message": "' + secret_event + '"',
            stderr="",
            returncode=0,
        )

        output = io.StringIO()
        with patch.object(
            live_monitoring,
            "_run_powershell",
            return_value=result,
        ), redirect_stdout(output):
            events = live_monitoring.collect_new_events(100)

        self.assertEqual(events, [])
        self.assertNotIn(secret_event, output.getvalue())

    def test_durable_failure_persists_and_prints_sanitized_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = CollectorState(
                Path(tmp) / "collector-state.db"
            )
            state.initialize_checkpoint(100)

            def sender(_url, _payload, **_kwargs):
                raise requests.RequestException(
                    "credential=durable-secret offline"
                )

            runtime = DurableCollectorRuntime(
                state,
                "https://siem.example.test/api/collector/v1/batches",
                hostname="HOST01",
                os_name="Windows-11",
                sender=sender,
                retry_base_seconds=2,
                retry_max_seconds=8,
                retry_jitter_ratio=0,
                clock=lambda: 1000.0,
            )
            runtime.enqueue_logs(
                [{"record_id": 101, "event_type": "FAILED_LOGIN"}],
                [101],
            )

            output = io.StringIO()
            with redirect_stdout(output):
                self.assertFalse(runtime.flush_pending())

            pending = state.pending()
            self.assertEqual(len(pending), 1)
            self.assertNotIn(
                "durable-secret",
                pending[0]["last_error"],
            )
            self.assertIn(
                "[REDACTED]",
                pending[0]["last_error"],
            )
            self.assertNotIn(
                "durable-secret",
                output.getvalue(),
            )


if __name__ == "__main__":
    unittest.main()
