import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

from backend.collector import collector
from backend.collector.raw_output import (
    RawOutputPolicyError,
    persist_raw_logs,
    raw_output_enabled,
    resolve_raw_output_path,
)


class S7DLegacyCollectorRawOutputTests(unittest.TestCase):
    def test_repository_default_disables_plaintext_raw_output(self):
        config_path = (
            Path(__file__).resolve().parents[2]
            / "backend"
            / "collector"
            / "config.json"
        )
        config = json.loads(config_path.read_text(encoding="utf-8"))

        self.assertIs(config["raw_output_enabled"], False)
        self.assertEqual(
            config["raw_output_file"],
            "output/raw_security_logs.json",
        )

    def test_raw_output_requires_explicit_boolean_true(self):
        self.assertFalse(raw_output_enabled({}))
        self.assertFalse(raw_output_enabled({"raw_output_enabled": "true"}))
        self.assertTrue(raw_output_enabled({"raw_output_enabled": True}))

    def test_raw_output_path_rejects_absolute_and_parent_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            with self.assertRaises(RawOutputPolicyError):
                resolve_raw_output_path(
                    str(base / "raw.json"),
                    base_dir=base,
                )
            with self.assertRaises(RawOutputPolicyError):
                resolve_raw_output_path(
                    "../raw.json",
                    base_dir=base,
                )

    def test_explicit_opt_in_writes_atomically_inside_runtime_root(self):
        logs = [{"RecordId": 101, "Id": 4625, "Message": "sensitive"}]
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = persist_raw_logs(
                logs,
                "output/raw.json",
                base_dir=base,
            )
            self.assertEqual(target, base / "output" / "raw.json")
            self.assertEqual(
                json.loads(target.read_text(encoding="utf-8")),
                logs,
            )
            self.assertFalse(
                target.with_name(target.name + ".tmp").exists()
            )

    def test_legacy_save_is_disabled_by_default(self):
        logs = [{"Message": "do not persist me"}]
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            collector.config,
            {
                "raw_output_enabled": False,
                "raw_output_file": "output/raw.json",
            },
            clear=False,
        ):
            target = collector.save_raw_logs(
                logs,
                base_dir=Path(tmp),
            )
            self.assertIsNone(target)
            self.assertFalse(
                (Path(tmp) / "output" / "raw.json").exists()
            )

    def test_legacy_save_can_be_explicitly_enabled(self):
        logs = [{"Message": "approved local evidence copy"}]
        with tempfile.TemporaryDirectory() as tmp:
            target = collector.save_raw_logs(
                logs,
                filename="output/raw.json",
                enabled=True,
                base_dir=Path(tmp),
            )
            self.assertEqual(
                json.loads(Path(target).read_text(encoding="utf-8")),
                logs,
            )

    def test_json_parse_error_does_not_print_raw_security_event(self):
        secret = "PRIVATE-SECURITY-EVENT-CONTENT"
        result = Mock(
            stdout='{"Message": "' + secret + '"',
            stderr="",
            returncode=0,
        )
        output = io.StringIO()
        with patch.object(
            collector.subprocess,
            "run",
            return_value=result,
        ), redirect_stdout(output):
            logs = collector.collect_security_logs(hours=1, max_events=1)

        self.assertEqual(logs, [])
        self.assertNotIn(secret, output.getvalue())


if __name__ == "__main__":
    unittest.main()
