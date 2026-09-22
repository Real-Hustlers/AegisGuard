import sqlite3
import unittest

from backend.storage.migrations import (
    LATEST_PLATFORM_SCHEMA_VERSION,
    ensure_platform_schema,
    get_platform_schema_version,
)


class PlatformSchemaTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute("PRAGMA foreign_keys = ON")

        # Minimal legacy structures that exist before the enterprise migration.
        self.conn.executescript(
            """
            CREATE TABLE incidents (
                incident_id TEXT PRIMARY KEY,
                status TEXT,
                timestamp TEXT
            );

            CREATE TABLE response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_key TEXT NOT NULL UNIQUE,
                incident_id TEXT,
                action_type TEXT NOT NULL,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_at TEXT NOT NULL
            );

            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            INSERT INTO incidents(incident_id, status, timestamp)
            VALUES ('legacy-1', 'SIMULATED', '2026-08-23T00:00:00Z');
            """
        )

    def tearDown(self):
        self.conn.close()

    def test_migration_is_idempotent_and_preserves_legacy_data(self):
        first = ensure_platform_schema(self.conn)
        second = ensure_platform_schema(self.conn)

        self.assertEqual(first, LATEST_PLATFORM_SCHEMA_VERSION)
        self.assertEqual(second, LATEST_PLATFORM_SCHEMA_VERSION)
        self.assertEqual(
            get_platform_schema_version(self.conn),
            LATEST_PLATFORM_SCHEMA_VERSION,
        )

        row = self.conn.execute(
            "SELECT status FROM incidents WHERE incident_id='legacy-1'"
        ).fetchone()
        self.assertEqual(row[0], "SIMULATED")

        migration_count = self.conn.execute(
            "SELECT COUNT(*) FROM platform_schema_migrations"
        ).fetchone()[0]
        self.assertEqual(migration_count, LATEST_PLATFORM_SCHEMA_VERSION)

    def test_required_enterprise_tables_exist(self):
        ensure_platform_schema(self.conn)
        tables = {
            row[0]
            for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        required = {
            "users",
            "sessions",
            "collectors",
            "assets",
            "events",
            "detections",
            "incidents",
            "incident_events",
            "response_actions",
            "audit_events",
            "model_metadata",
            "settings",
            "platform_schema_migrations",
            "collector_ingest_batches",
        }
        self.assertTrue(required.issubset(tables))

    def test_legacy_tables_receive_platform_columns(self):
        ensure_platform_schema(self.conn)
        incident_columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(incidents)")
        }
        response_columns = {
            row[1]
            for row in self.conn.execute("PRAGMA table_info(response_actions)")
        }

        self.assertIn("lifecycle_status", incident_columns)
        self.assertIn("assigned_user_id", incident_columns)
        self.assertIn("requested_by_user_id", response_columns)
        self.assertIn("simulation_result", response_columns)

        collector_columns = {
            row[1]
            for row in self.conn.execute("PRAGMA table_info(collectors)")
        }
        self.assertIn("credential_rotation_id", collector_columns)
        self.assertIn("credential_rotated_at", collector_columns)
        self.assertIn("credential_recovery_id", collector_columns)
        self.assertIn("credential_recovered_at", collector_columns)


if __name__ == "__main__":
    unittest.main()
