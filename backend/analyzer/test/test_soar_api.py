import sys
import unittest
from pathlib import Path

from backend.analyzer import app as analyzer_app


class SoarApiTests(unittest.TestCase):
    def setUp(self):
        self.path = Path.cwd() / ".aegisguard_soar_api_test.db"
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                candidate.unlink()
        self.databases = [module for module in (
            sys.modules.get("database"), sys.modules.get("backend.analyzer.database")
        ) if module]
        self.original = [(database, database.DB_PATH, database._schema_initialized) for database in self.databases]
        for database in self.databases:
            database.DB_PATH = self.path
            database._schema_initialized = False
        self.client = analyzer_app.app.test_client()

    def tearDown(self):
        for database, path, initialized in self.original:
            database.DB_PATH = path
            database._schema_initialized = initialized
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(str(self.path) + suffix)
            if candidate.exists():
                candidate.unlink()

    def test_recent_actions_api_and_manual_dry_run_block(self):
        settings = self.client.get("/api/incidents/settings").get_json()
        self.assertEqual(settings["soar_mode"], "MANUAL")
        self.assertTrue(settings["soar_dry_run"])
        action = self.client.post("/api/soar/block-ip", json={
            "ip": "8.8.8.8", "reason": "controlled demo"
        })
        self.assertEqual(action.status_code, 200)
        self.assertEqual(action.get_json()["status"], "DRY_RUN")
        recent = self.client.get("/api/response-actions")
        self.assertEqual(recent.status_code, 200)
        self.assertEqual(len(recent.get_json()), 1)
        self.assertEqual(recent.get_json()[0]["target"], "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
