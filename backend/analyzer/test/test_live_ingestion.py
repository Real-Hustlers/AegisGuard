import sys
import time
import unittest
from pathlib import Path

from backend.analyzer import app as analyzer_app


class LiveIngestionTests(unittest.TestCase):
    """End-to-end tests for the real Collector HTTP contract and SQLite APIs."""

    def setUp(self):
        self.test_db_path = Path.cwd() / ".aegisguard_live_ingestion_test.db"
        for path in (
            self.test_db_path,
            Path(f"{self.test_db_path}-wal"),
            Path(f"{self.test_db_path}-shm"),
        ):
            if path.exists():
                path.unlink()
        self.databases = [
            module for module in (
                sys.modules.get("database"),
                sys.modules.get("backend.analyzer.database"),
            ) if module is not None
        ]
        self.original_database_state = [
            (database, database.DB_PATH, database._schema_initialized)
            for database in self.databases
        ]
        for database in self.databases:
            database.DB_PATH = self.test_db_path
            database._schema_initialized = False
        self.client = analyzer_app.app.test_client()

    def tearDown(self):
        for database, db_path, schema_state in self.original_database_state:
            database.DB_PATH = db_path
            database._schema_initialized = schema_state
        for path in (
            self.test_db_path,
            Path(f"{self.test_db_path}-wal"),
            Path(f"{self.test_db_path}-shm"),
        ):
            if path.exists():
                path.unlink()

    @staticmethod
    def _event(record_id, event_type="LOGON_SUCCESS", hostname="LAPTOP-4R1PPU2C"):
        return {
            "record_id": record_id,
            "hostname": hostname,
            "timestamp": "2026-08-22 10:30:00",
            "event_type": event_type,
            "user": "winny",
            "event": f"Windows {event_type}",
            "raw_log": f"Windows {event_type}",
            "severity": "Information",
            "source_ip": "10.15.63.24",
        }

    def _upload(self, logs):
        return self.client.post("/api/upload_logs", json={
            "machine_id": "LAPTOP-4R1PPU2C",
            "hostname": "LAPTOP-4R1PPU2C",
            "os": "Windows 11",
            "logs": logs,
        })

    def test_new_event_retry_and_api_counts_are_immediately_consistent(self):
        event = self._event(734467, "FAILED_LOGIN")
        first = self._upload([event])
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.get_json()["new_logs_added"], 1)

        duplicate = self._upload([event])
        self.assertEqual(duplicate.status_code, 200)
        self.assertEqual(duplicate.get_json()["new_logs_added"], 0)

        events = self.client.get("/api/events")
        self.assertEqual(events.status_code, 200)
        self.assertEqual(len(events.get_json()), 1)

        filtered = self.client.get("/api/events?hostname=LAPTOP-4R1PPU2C")
        self.assertEqual(len(filtered.get_json()), 1)
        self.assertEqual(self.client.get("/api/events?hostname=OTHER").get_json(), [])

        dashboard = self.client.get("/api/dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertEqual(dashboard.get_json()["events"], 1)
        self.assertIn("no-store", dashboard.headers["Cache-Control"])

        saved = events.get_json()[0]
        self.assertEqual(saved["ml_prediction"], "BRUTE_FORCE")
        self.assertEqual(saved["threat_level"], "HIGH")
        self.assertEqual(saved["threat_score"], 80)

    def test_25_event_batch_is_incremental_and_fast(self):
        batch = [self._event(800000 + index) for index in range(25)]
        started = time.perf_counter()
        response = self._upload(batch)
        elapsed = time.perf_counter() - started
        data = response.get_json()

        print(f"25-event live upload: {elapsed:.3f}s ({data['processing_ms']} ms server)")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["new_logs_added"], 25)
        self.assertLess(elapsed, 5.0)
        self.assertEqual(len(self.client.get("/api/events").get_json()), 25)
        self.assertEqual(self.client.get("/api/dashboard").get_json()["events"], 25)

    def test_three_acknowledged_windows_records_are_immediately_queryable(self):
        """Regression for 739095/739097/739162 on the physical Collector."""

        record_ids = (739095, 739097, 739162)
        baseline = len(self.client.get("/api/events").get_json())

        for offset, record_id in enumerate(record_ids, start=1):
            event = self._event(record_id)
            event["timestamp"] = f"2026-08-22 13:{15 + offset:02d}:00"
            response = self._upload([event])
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["new_logs_added"], 1)

            all_events = self.client.get("/api/events").get_json()
            host_events = self.client.get(
                "/api/events?hostname=LAPTOP-4R1PPU2C"
            ).get_json()
            conn = analyzer_app.get_connection()
            try:
                db_count = conn.execute("SELECT COUNT(*) FROM security_logs").fetchone()[0]
                db_record = conn.execute(
                    "SELECT record_id FROM security_logs WHERE hostname = ? AND record_id = ?",
                    ("LAPTOP-4R1PPU2C", record_id),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(len(all_events), baseline + offset)
            self.assertEqual(db_count, baseline + offset)
            self.assertIsNotNone(db_record)
            self.assertEqual(
                self.client.get("/api/dashboard").get_json()["events"],
                baseline + offset,
            )
            matching = [
                event for event in host_events
                if str(event["record_id"]) == str(record_id)
            ]
            self.assertEqual(len(matching), 1)
            self.assertEqual(matching[0]["id"], f"windows:laptop-4r1ppu2c:{record_id}")

        retry = self._upload([
            self._event(record_id) for record_id in record_ids
        ])
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.get_json()["new_logs_added"], 0)
        self.assertEqual(len(self.client.get("/api/events").get_json()), baseline + 3)


if __name__ == "__main__":
    unittest.main()
