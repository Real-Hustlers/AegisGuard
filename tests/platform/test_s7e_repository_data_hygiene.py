import json
import unittest
from pathlib import Path


class S7ERepositoryDataHygieneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[2]

    def test_legacy_raw_security_log_artifacts_are_absent(self):
        forbidden = (
            self.repo_root / "raw_security_logs.json",
            self.repo_root / "backend" / "collector" / "raw_security_logs.json",
        )

        for path in forbidden:
            self.assertFalse(
                path.exists(),
                f"runtime raw-security artifact must not be committed: {path}",
            )

    def test_raw_security_log_artifact_name_is_gitignored(self):
        gitignore = (
            self.repo_root / ".gitignore"
        ).read_text(encoding="utf-8").splitlines()

        self.assertIn(
            "raw_security_logs.json",
            {line.strip() for line in gitignore},
        )

    def test_legacy_collector_raw_output_remains_disabled_by_default(self):
        config = json.loads(
            (
                self.repo_root
                / "backend"
                / "collector"
                / "config.json"
            ).read_text(encoding="utf-8")
        )

        self.assertIs(
            config.get("raw_output_enabled"),
            False,
        )
        self.assertEqual(
            config.get("raw_output_file"),
            "output/raw_security_logs.json",
        )


if __name__ == "__main__":
    unittest.main()
