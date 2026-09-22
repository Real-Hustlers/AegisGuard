import sqlite3
import unittest

from backend.storage.collector_identity import (
    CollectorAuthenticationError,
    CollectorEnrollmentError,
    CollectorRevokedError,
    authenticate_collector,
    credential_fingerprint,
    enroll_collector,
    revoke_collector,
)
from backend.storage.migrations import ensure_platform_schema


class CollectorIdentityTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        ensure_platform_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def enroll(self, collector_id="collector-1", hostname="HOST01"):
        return enroll_collector(
            self.conn,
            collector_id,
            hostname,
            version="0.1.0",
            metadata={"os": "Windows-11"},
            credential_factory=lambda: "device-secret-001",
        )

    def test_enrollment_returns_secret_once_and_stores_only_fingerprint(self):
        result = self.enroll()

        self.assertEqual(result["collector_id"], "collector-1")
        self.assertEqual(result["status"], "ENROLLED")
        self.assertEqual(result["credential"], "device-secret-001")

        row = self.conn.execute(
            """
            SELECT hostname, status, credential_fingerprint, metadata_json
            FROM collectors
            WHERE collector_id='collector-1'
            """
        ).fetchone()

        self.assertEqual(row[0], "HOST01")
        self.assertEqual(row[1], "ENROLLED")
        self.assertEqual(
            row[2],
            credential_fingerprint("device-secret-001"),
        )
        self.assertNotEqual(row[2], "device-secret-001")
        self.assertIn('"os":"Windows-11"', row[3])

    def test_duplicate_enrollment_does_not_generate_replacement_credential(self):
        self.enroll()

        calls = []

        def factory():
            calls.append(True)
            return "replacement-secret"

        with self.assertRaisesRegex(
            CollectorEnrollmentError,
            "already enrolled",
        ):
            enroll_collector(
                self.conn,
                "collector-1",
                "HOST01",
                credential_factory=factory,
            )

        self.assertEqual(calls, [])

        row = self.conn.execute(
            """
            SELECT credential_fingerprint
            FROM collectors
            WHERE collector_id='collector-1'
            """
        ).fetchone()
        self.assertEqual(
            row[0],
            credential_fingerprint("device-secret-001"),
        )

    def test_valid_authentication_updates_last_seen_and_binds_hostname(self):
        self.enroll()

        identity = authenticate_collector(
            self.conn,
            "collector-1",
            "device-secret-001",
            hostname="HOST01",
            seen_at="2026-09-22T10:00:00Z",
        )

        self.assertEqual(identity["collector_id"], "collector-1")
        self.assertEqual(identity["hostname"], "HOST01")
        self.assertEqual(identity["status"], "ENROLLED")
        self.assertEqual(
            identity["last_seen_at"],
            "2026-09-22T10:00:00Z",
        )

        with self.assertRaisesRegex(
            CollectorAuthenticationError,
            "hostname mismatch",
        ):
            authenticate_collector(
                self.conn,
                "collector-1",
                "device-secret-001",
                hostname="OTHER-HOST",
            )

    def test_unknown_and_wrong_credentials_fail_closed(self):
        self.enroll()

        with self.assertRaisesRegex(
            CollectorAuthenticationError,
            "unknown collector",
        ):
            authenticate_collector(
                self.conn,
                "collector-missing",
                "device-secret-001",
            )

        with self.assertRaisesRegex(
            CollectorAuthenticationError,
            "invalid collector credential",
        ):
            authenticate_collector(
                self.conn,
                "collector-1",
                "wrong-secret",
            )

    def test_revoked_collector_cannot_authenticate(self):
        self.enroll()

        self.assertTrue(
            revoke_collector(
                self.conn,
                "collector-1",
                revoked_at="2026-09-22T11:00:00Z",
            )
        )
        self.assertFalse(
            revoke_collector(
                self.conn,
                "collector-1",
                revoked_at="2026-09-22T11:01:00Z",
            )
        )

        row = self.conn.execute(
            """
            SELECT status, revoked_at
            FROM collectors
            WHERE collector_id='collector-1'
            """
        ).fetchone()
        self.assertEqual(row[0], "REVOKED")
        self.assertEqual(row[1], "2026-09-22T11:00:00Z")

        with self.assertRaisesRegex(
            CollectorRevokedError,
            "revoked",
        ):
            authenticate_collector(
                self.conn,
                "collector-1",
                "device-secret-001",
                hostname="HOST01",
            )


if __name__ == "__main__":
    unittest.main()
