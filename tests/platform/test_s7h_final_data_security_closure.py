import io
import subprocess
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from backend.collector import collector
from backend.collector import live_monitoring


class S7HFinalDataSecurityClosureTests(unittest.TestCase):
    def test_live_server_error_response_is_secret_safe(self):
        response = Mock(
            status_code=500,
            text='{"credential":"server-secret","status":"error"}',
        )
        response.json.return_value = {
            "credential": "server-secret",
            "status": "error",
        }

        output = io.StringIO()
        with patch.object(
            live_monitoring.requests,
            "post",
            return_value=response,
        ), patch.object(
            live_monitoring,
            "UPLOAD_RETRIES",
            1,
        ), redirect_stdout(output):
            self.assertFalse(
                live_monitoring.send_logs(
                    [{"event_type": "FAILED_LOGIN"}]
                )
            )

        text = output.getvalue()
        self.assertNotIn("server-secret", text)
        self.assertIn("[REDACTED]", text)

    def test_latest_record_probe_does_not_print_raw_stdout(self):
        result = Mock(
            stdout=(
                '{"RecordId": 123, '
                '"credential": "probe-secret"}'
            ),
            stderr="",
            returncode=0,
        )

        output = io.StringIO()
        with patch.object(
            live_monitoring,
            "_run_powershell",
            return_value=result,
        ), redirect_stdout(output):
            record_id = live_monitoring.get_latest_record_id()

        self.assertEqual(record_id, 123)
        self.assertNotIn("probe-secret", output.getvalue())

    def test_legacy_collector_banner_uses_safe_url_projection(self):
        source = Path(collector.__file__).read_text(
            encoding="utf-8",
        )

        self.assertNotIn(
            'f"\\nAnalyzer URL : {ANALYZER}"',
            source,
        )
        self.assertIn(
            "sanitize_url_for_diagnostics(ANALYZER)",
            source,
        )

    def test_runtime_raw_artifacts_are_not_tracked(self):
        repo_root = Path(__file__).resolve().parents[2]
        tracked = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.splitlines()

        banned = {
            "raw_security_logs.json",
            "backend/collector/raw_security_logs.json",
            "backend/analyzer/output/merged_logs.json",
            "backend/analyzer/output/classified_logs.json",
        }

        self.assertTrue(
            banned.isdisjoint(set(tracked)),
            msg=(
                "runtime raw/generated security artifacts must not "
                "be committed to the repository"
            ),
        )


if __name__ == "__main__":
    unittest.main()
