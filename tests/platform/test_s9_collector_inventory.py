import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask

from backend.analyzer.app_authorization import (
    ALL_APPLICATION_ROLES,
    required_roles_for_request,
)
from backend.analyzer.asset_api import (
    create_asset_management_blueprint,
)
from backend.storage.collector_health import (
    record_collector_heartbeat,
)
from backend.storage.collector_identity import (
    enroll_collector,
    revoke_collector,
)
from backend.storage.collector_inventory import (
    CollectorInventoryNotFound,
    get_collector_inventory,
    list_collector_inventory,
)
from backend.storage.migrations import ensure_platform_schema


CERTIFICATE = "a" * 64


class CollectorInventoryTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        ensure_platform_schema(self.conn)

        enroll_collector(
            self.conn,
            "collector-1",
            "HOST01",
            version="0.1.0",
            display_name="Finance workstation",
            metadata={"os": "Windows"},
            credential_factory=lambda: "device-secret-001",
            certificate_fingerprint=CERTIFICATE,
        )

        record_collector_heartbeat(
            self.conn,
            "collector-1",
            peer_ip="10.10.20.15",
            mtls_required=True,
            mtls_verified=True,
            certificate_fingerprint=CERTIFICATE,
            reported_version="0.2.0",
            reported_health={
                "status": "BACKLOG",
                "pending_batches": 3,
                "checkpoint": 1200,
                "collection_cursor": 1300,
                "retry_in_seconds": 2.5,
                "last_successful_ack_at": 12345.0,
                "certificate_rotation_pending": False,
            },
        )

        self.conn.execute(
            """
            INSERT INTO assets(
                asset_id,
                collector_id,
                hostname,
                os,
                primary_ip,
                first_seen_at,
                last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "asset-1",
                "collector-1",
                "HOST01",
                "Windows 11",
                "10.10.20.15",
                "2026-09-23 06:00:00",
                "2026-09-23 07:00:00",
            ),
        )

        states = [
            "QUEUED",
            "QUEUED",
            "PROCESSING",
            "FAILED",
            "PROCESSED",
            "PROCESSED",
        ]

        for index, state in enumerate(states, start=1):
            self.conn.execute(
                """
                INSERT INTO collector_ingest_batches(
                    batch_id,
                    collector_id,
                    hostname,
                    payload_json,
                    event_count,
                    state
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    f"batch-{index}",
                    "collector-1",
                    "HOST01",
                    "{}",
                    10,
                    state,
                ),
            )

        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_inventory_separates_server_and_reported_state(self):
        collector = get_collector_inventory(
            self.conn,
            "collector-1",
        )

        self.assertEqual(
            collector["identity"]["collector_id"],
            "collector-1",
        )
        self.assertEqual(
            collector["identity"]["status"],
            "ENROLLED",
        )

        self.assertEqual(
            collector["server_observed"]["peer_ip"],
            "10.10.20.15",
        )
        self.assertTrue(
            collector["server_observed"]["credential_authenticated"]
        )
        self.assertTrue(
            collector["server_observed"]["mtls_required"]
        )
        self.assertTrue(
            collector["server_observed"]["mtls_verified"]
        )

        self.assertEqual(
            collector["collector_reported"]["transport_status"],
            "BACKLOG",
        )
        self.assertEqual(
            collector["collector_reported"]["pending_batches"],
            3,
        )
        self.assertEqual(
            collector["collector_reported"]["checkpoint"],
            1200,
        )

    def test_sensitive_fingerprints_are_never_exposed(self):
        collector = get_collector_inventory(
            self.conn,
            "collector-1",
        )

        serialized = json.dumps(
            collector,
            sort_keys=True,
        )

        self.assertNotIn(
            "credential_fingerprint",
            serialized,
        )
        self.assertNotIn(
            "certificate_fingerprint",
            serialized,
        )
        self.assertNotIn(
            CERTIFICATE,
            serialized,
        )
        self.assertNotIn(
            "device-secret-001",
            serialized,
        )

    def test_security_state_is_server_derived(self):
        collector = get_collector_inventory(
            self.conn,
            "collector-1",
        )

        self.assertEqual(
            collector["security"]["credential_state"],
            "ENROLLED",
        )
        self.assertEqual(
            collector["security"]["certificate_state"],
            "BOUND",
        )

    def test_server_queue_counts_are_derived_from_durable_batches(self):
        collector = get_collector_inventory(
            self.conn,
            "collector-1",
        )

        self.assertEqual(
            collector["server_queue"],
            {
                "queued": 2,
                "processing": 1,
                "processed": 2,
                "failed": 1,
                "total": 6,
            },
        )

    def test_linked_assets_are_returned_from_asset_registry(self):
        collector = get_collector_inventory(
            self.conn,
            "collector-1",
        )

        self.assertEqual(
            len(collector["assets"]),
            1,
        )

        asset = collector["assets"][0]

        self.assertEqual(
            asset["asset_id"],
            "asset-1",
        )
        self.assertEqual(
            asset["hostname"],
            "HOST01",
        )
        self.assertEqual(
            asset["primary_ip"],
            "10.10.20.15",
        )

    def test_revoked_collector_is_explicitly_represented(self):
        revoke_collector(
            self.conn,
            "collector-1",
            revoked_at="2026-09-23T08:00:00Z",
        )

        collector = get_collector_inventory(
            self.conn,
            "collector-1",
        )

        self.assertEqual(
            collector["identity"]["status"],
            "REVOKED",
        )
        self.assertEqual(
            collector["security"]["credential_state"],
            "REVOKED",
        )
        self.assertEqual(
            collector["security"]["certificate_state"],
            "REVOKED",
        )

    def test_recent_server_contact_is_current(self):
        self.conn.execute(
            """
            UPDATE collectors
            SET last_seen_at = ?,
                last_heartbeat_at = ?
            WHERE collector_id = ?
            """,
            (
                "2026-09-23T07:59:40Z",
                "2026-09-23T07:59:30Z",
                "collector-1",
            ),
        )
        self.conn.commit()

        collector = get_collector_inventory(
            self.conn,
            "collector-1",
            now=datetime(
                2026, 9, 23, 8, 0, 0,
                tzinfo=timezone.utc,
            ),
            stale_after_seconds=90,
        )

        self.assertEqual(
            collector["liveness"]["state"],
            "CURRENT",
        )
        self.assertEqual(
            collector["liveness"]["last_contact_source"],
            "authenticated_activity",
        )
        self.assertEqual(
            collector["liveness"]["age_seconds"],
            20.0,
        )
        self.assertEqual(
            collector["liveness"]["stale_after_seconds"],
            90.0,
        )

    def test_old_server_contact_is_stale(self):
        self.conn.execute(
            """
            UPDATE collectors
            SET last_seen_at = ?,
                last_heartbeat_at = ?
            WHERE collector_id = ?
            """,
            (
                "2026-09-23T07:57:00Z",
                "2026-09-23T07:58:00Z",
                "collector-1",
            ),
        )
        self.conn.commit()

        collector = get_collector_inventory(
            self.conn,
            "collector-1",
            now=datetime(
                2026, 9, 23, 8, 0, 0,
                tzinfo=timezone.utc,
            ),
            stale_after_seconds=90,
        )

        self.assertEqual(
            collector["liveness"]["state"],
            "STALE",
        )
        self.assertEqual(
            collector["liveness"]["last_contact_source"],
            "heartbeat",
        )
        self.assertEqual(
            collector["liveness"]["age_seconds"],
            120.0,
        )

    def test_collector_without_server_contact_is_never_seen(self):
        enroll_collector(
            self.conn,
            "collector-never",
            "NEVER-SEEN",
            credential_factory=lambda: "never-secret",
        )

        collector = get_collector_inventory(
            self.conn,
            "collector-never",
            now=datetime(
                2026, 9, 23, 8, 0, 0,
                tzinfo=timezone.utc,
            ),
            stale_after_seconds=90,
        )

        self.assertEqual(
            collector["liveness"]["state"],
            "NEVER_SEEN",
        )
        self.assertIsNone(
            collector["liveness"]["last_contact_at"]
        )
        self.assertIsNone(
            collector["liveness"]["age_seconds"]
        )

    def test_revoked_identity_overrides_recent_contact(self):
        self.conn.execute(
            """
            UPDATE collectors
            SET last_seen_at = ?
            WHERE collector_id = ?
            """,
            (
                "2026-09-23T07:59:55Z",
                "collector-1",
            ),
        )
        self.conn.commit()

        revoke_collector(
            self.conn,
            "collector-1",
            revoked_at="2026-09-23T07:59:58Z",
        )

        collector = get_collector_inventory(
            self.conn,
            "collector-1",
            now=datetime(
                2026, 9, 23, 8, 0, 0,
                tzinfo=timezone.utc,
            ),
            stale_after_seconds=90,
        )

        self.assertEqual(
            collector["liveness"]["state"],
            "REVOKED",
        )

    def test_stale_threshold_must_be_positive(self):
        with self.assertRaisesRegex(
            ValueError,
            "stale_after_seconds",
        ):
            get_collector_inventory(
                self.conn,
                "collector-1",
                stale_after_seconds=0,
            )

    def test_list_is_deterministic_and_unknown_id_fails(self):
        results = list_collector_inventory(
            self.conn
        )

        self.assertEqual(
            [item["identity"]["collector_id"] for item in results],
            ["collector-1"],
        )

        with self.assertRaises(
            CollectorInventoryNotFound
        ):
            get_collector_inventory(
                self.conn,
                "missing-collector",
            )


class CollectorInventoryApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "s9.db"

        conn = self.connection_factory()

        enroll_collector(
            conn,
            "collector-api",
            "API-HOST",
            credential_factory=lambda: "api-secret",
        )

        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def connection_factory(self):
        conn = sqlite3.connect(
            str(self.db_path)
        )
        ensure_platform_schema(conn)
        return conn

    def make_app(self):
        app = Flask(__name__)

        app.register_blueprint(
            create_asset_management_blueprint(
                self.connection_factory
            )
        )

        app.testing = True
        return app

    def test_api_lists_and_fetches_collectors(self):
        client = self.make_app().test_client()

        listed = client.get(
            "/api/collectors"
        )

        self.assertEqual(
            listed.status_code,
            200,
        )

        payload = listed.get_json()

        self.assertEqual(
            payload["count"],
            1,
        )
        self.assertEqual(
            payload["collectors"][0]["identity"]["collector_id"],
            "collector-api",
        )

        detail = client.get(
            "/api/collectors/collector-api"
        )

        self.assertEqual(
            detail.status_code,
            200,
        )
        self.assertEqual(
            detail.get_json()["collector"]["identity"]["hostname"],
            "API-HOST",
        )

    def test_unknown_collector_returns_404(self):
        client = self.make_app().test_client()

        response = client.get(
            "/api/collectors/missing"
        )

        self.assertEqual(
            response.status_code,
            404,
        )
        self.assertEqual(
            response.get_json()["error"],
            "collector_not_found",
        )

    def test_inventory_api_is_read_only(self):
        client = self.make_app().test_client()

        self.assertEqual(
            client.post(
                "/api/collectors",
                json={},
            ).status_code,
            405,
        )

        self.assertEqual(
            client.delete(
                "/api/collectors/collector-api"
            ).status_code,
            405,
        )

    def test_inventory_get_routes_use_existing_human_rbac_policy(self):
        self.assertEqual(
            required_roles_for_request(
                "/api/collectors",
                "GET",
            ),
            ALL_APPLICATION_ROLES,
        )
        self.assertEqual(
            required_roles_for_request(
                "/api/collectors/collector-api",
                "GET",
            ),
            ALL_APPLICATION_ROLES,
        )


if __name__ == "__main__":
    unittest.main()
