import base64
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.collector.credential_store import (
    CredentialProtectionError,
    WindowsDPAPICredentialProtector,
)
from backend.collector.state import CollectorState


class _TestProtector:
    PREFIX = b"TEST-PROTECTED:"

    def protect(self, plaintext: bytes) -> bytes:
        value = bytes(plaintext)
        if not value:
            raise CredentialProtectionError("empty plaintext")
        return self.PREFIX + value[::-1]

    def unprotect(self, protected: bytes) -> bytes:
        value = bytes(protected)
        if not value.startswith(self.PREFIX):
            raise CredentialProtectionError("invalid protected value")
        return value[len(self.PREFIX):][::-1]


class _RejectingProtector:
    def protect(self, plaintext: bytes) -> bytes:
        raise CredentialProtectionError("protect failed")

    def unprotect(self, protected: bytes) -> bytes:
        raise CredentialProtectionError("unprotect failed")


class CollectorCredentialProtectionTests(unittest.TestCase):
    def test_new_credential_is_protected_at_rest(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collector-state.db"
            state = CollectorState(
                path,
                credential_protector=_TestProtector(),
            )

            state.store_collector_credential("device-secret-001")
            self.assertEqual(
                state.get_collector_credential(),
                "device-secret-001",
            )

            conn = sqlite3.connect(str(path))
            try:
                rows = dict(
                    conn.execute(
                        """
                        SELECT key, value
                        FROM collector_state
                        WHERE key LIKE 'collector_credential%'
                        """
                    ).fetchall()
                )
            finally:
                conn.close()

            self.assertNotIn("collector_credential", rows)
            self.assertIn("collector_credential_protected_v1", rows)
            self.assertNotIn(
                "device-secret-001",
                rows["collector_credential_protected_v1"],
            )

            decoded = base64.b64decode(
                rows["collector_credential_protected_v1"]
            )
            self.assertTrue(decoded.startswith(_TestProtector.PREFIX))

    def test_legacy_plaintext_credential_migrates_on_first_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collector-state.db"
            initial = CollectorState(
                path,
                credential_protector=_TestProtector(),
            )

            conn = initial._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO collector_state(key, value)
                    VALUES ('collector_credential', 'legacy-secret')
                    """
                )
                conn.commit()
            finally:
                conn.close()

            reopened = CollectorState(
                path,
                credential_protector=_TestProtector(),
            )
            self.assertEqual(
                reopened.get_collector_credential(),
                "legacy-secret",
            )

            conn = sqlite3.connect(str(path))
            try:
                rows = dict(
                    conn.execute(
                        """
                        SELECT key, value
                        FROM collector_state
                        WHERE key LIKE 'collector_credential%'
                        """
                    ).fetchall()
                )
            finally:
                conn.close()

            self.assertNotIn("collector_credential", rows)
            self.assertIn("collector_credential_protected_v1", rows)

    def test_failed_legacy_migration_keeps_plaintext_for_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collector-state.db"
            state = CollectorState(
                path,
                credential_protector=_TestProtector(),
            )
            conn = state._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO collector_state(key, value)
                    VALUES ('collector_credential', 'legacy-secret')
                    """
                )
                conn.commit()
            finally:
                conn.close()

            broken = CollectorState(
                path,
                credential_protector=_RejectingProtector(),
            )
            with self.assertRaisesRegex(
                CredentialProtectionError,
                "protect failed",
            ):
                broken.get_collector_credential()

            conn = sqlite3.connect(str(path))
            try:
                value = conn.execute(
                    """
                    SELECT value
                    FROM collector_state
                    WHERE key='collector_credential'
                    """
                ).fetchone()[0]
            finally:
                conn.close()

            self.assertEqual(value, "legacy-secret")

    def test_corrupt_protected_credential_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "collector-state.db"
            state = CollectorState(
                path,
                credential_protector=_TestProtector(),
            )
            conn = state._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO collector_state(key, value)
                    VALUES ('collector_credential_protected_v1', ?)
                    """,
                    (
                        base64.b64encode(
                            b"not-a-valid-protected-value"
                        ).decode("ascii"),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            with self.assertRaises(CredentialProtectionError):
                state.get_collector_credential()

    @unittest.skipUnless(
        os.name == "nt",
        "Windows DPAPI integration requires Windows",
    )
    def test_windows_dpapi_round_trip(self):
        protector = WindowsDPAPICredentialProtector()
        plaintext = b"device-secret-dpapi-test"
        protected = protector.protect(plaintext)

        self.assertNotEqual(protected, plaintext)
        self.assertEqual(
            protector.unprotect(protected),
            plaintext,
        )


if __name__ == "__main__":
    unittest.main()
