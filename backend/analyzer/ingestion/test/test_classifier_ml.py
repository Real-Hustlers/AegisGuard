import json
import tempfile
import unittest
from pathlib import Path

from backend.analyzer.ingestion.classifier import classify_logs


class ClassifierMLIntegrationTest(unittest.TestCase):
    def test_classify_logs_adds_ml_prediction_and_threat_fields(self):
        sample_logs = [
            {
                "timestamp": "2026-07-14T09:30:10Z",
                "event_type": "FAILED_LOGIN",
                "user": "administrator",
                "hostname": "Finance-PC",
                "source_ip": "192.168.1.200",
                "destination_ip": "",
                "process": "winlogon.exe",
                "file_path": "",
                "severity": "MEDIUM",
                "raw_log": "An account failed to log on."
            },
            {
                "timestamp": "2026-07-14T09:31:15Z",
                "event_type": "FAILED_LOGIN",
                "user": "administrator",
                "hostname": "Finance-PC",
                "source_ip": "192.168.1.200",
                "destination_ip": "",
                "process": "winlogon.exe",
                "file_path": "",
                "severity": "MEDIUM",
                "raw_log": "An account failed to log on."
            }
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "merged.json"
            output_path = Path(tmpdir) / "classified.json"
            input_path.write_text(json.dumps(sample_logs), encoding="utf-8")

            classify_logs(str(input_path), str(output_path))

            classified = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(len(classified), 2)
        self.assertIn("ml_prediction", classified[0])
        self.assertIn("threat_level", classified[0])
        self.assertIn("threat_score", classified[0])


if __name__ == "__main__":
    unittest.main()
