"""Durable local collector spool and checkpoint storage."""

import base64
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.collector.credential_store import (
    CredentialProtectionError,
    default_credential_protector,
)


class CollectorState:
    def __init__(self, path, credential_protector=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.credential_protector = (
            credential_protector
            if credential_protector is not None
            else default_credential_protector()
        )
        self._ensure_schema()

    def _connect(self):
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    def _ensure_schema(self):
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS collector_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS outbound_batches (
                    batch_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    max_record_id INTEGER,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    last_attempt_at REAL,
                    next_attempt_at REAL
                );
                """
            )

            # S2B-3 collector-local migration for state databases created by
            # S2A/S2B-2. This is separate from the analyzer platform schema.
            columns = {
                str(row[1])
                for row in conn.execute(
                    "PRAGMA table_info(outbound_batches)"
                ).fetchall()
            }
            if "last_attempt_at" not in columns:
                conn.execute(
                    "ALTER TABLE outbound_batches ADD COLUMN last_attempt_at REAL"
                )
            if "next_attempt_at" not in columns:
                conn.execute(
                    "ALTER TABLE outbound_batches ADD COLUMN next_attempt_at REAL"
                )

            conn.commit()
        finally:
            conn.close()

    def get_or_create_collector_id(self) -> str:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key='collector_id'"
            ).fetchone()
            if row:
                return str(row["value"])

            collector_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO collector_state(key, value) VALUES ('collector_id', ?)",
                (collector_id,),
            )
            conn.commit()
            return collector_id
        finally:
            conn.close()

    _PROTECTED_CREDENTIAL_KEY = "collector_credential_protected_v1"
    _LEGACY_CREDENTIAL_KEY = "collector_credential"

    def _protect_credential_value(self, credential: str) -> str:
        value = str(credential or "").strip()
        if not value:
            raise ValueError("collector credential must not be empty")

        protected = self.credential_protector.protect(
            value.encode("utf-8")
        )
        if not protected:
            raise CredentialProtectionError(
                "credential protector returned an empty value"
            )
        return base64.b64encode(protected).decode("ascii")

    def _unprotect_credential_value(self, encoded: str) -> str:
        try:
            protected = base64.b64decode(
                str(encoded).encode("ascii"),
                validate=True,
            )
        except Exception as exc:
            raise CredentialProtectionError(
                "protected collector credential is not valid Base64"
            ) from exc

        plaintext = self.credential_protector.unprotect(protected)
        try:
            value = plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CredentialProtectionError(
                "protected collector credential is not valid UTF-8"
            ) from exc

        if not value:
            raise CredentialProtectionError(
                "protected collector credential is empty"
            )
        return value

    def get_collector_credential(self) -> Optional[str]:
        """Return the protected device credential, migrating S3-1 plaintext."""

        conn = self._connect()
        try:
            protected_row = conn.execute(
                """
                SELECT value
                FROM collector_state
                WHERE key = ?
                """,
                (self._PROTECTED_CREDENTIAL_KEY,),
            ).fetchone()

            if protected_row is not None:
                value = self._unprotect_credential_value(
                    str(protected_row["value"])
                )
                conn.execute(
                    "DELETE FROM collector_state WHERE key = ?",
                    (self._LEGACY_CREDENTIAL_KEY,),
                )
                conn.commit()
                return value

            legacy_row = conn.execute(
                """
                SELECT value
                FROM collector_state
                WHERE key = ?
                """,
                (self._LEGACY_CREDENTIAL_KEY,),
            ).fetchone()
            if legacy_row is None:
                return None

            legacy_value = str(legacy_row["value"])
            encoded = self._protect_credential_value(legacy_value)

            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO collector_state(key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (self._PROTECTED_CREDENTIAL_KEY, encoded),
            )
            conn.execute(
                "DELETE FROM collector_state WHERE key = ?",
                (self._LEGACY_CREDENTIAL_KEY,),
            )
            conn.commit()
            return legacy_value
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def store_collector_credential(self, credential: str) -> None:
        """Protect and persist the device credential for restart continuity."""

        encoded = self._protect_credential_value(credential)

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO collector_state(key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (self._PROTECTED_CREDENTIAL_KEY, encoded),
            )
            conn.execute(
                "DELETE FROM collector_state WHERE key = ?",
                (self._LEGACY_CREDENTIAL_KEY,),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    _PENDING_RECOVERY_ID_KEY = "collector_credential_recovery_pending_id"
    _PENDING_RECOVERY_CREDENTIAL_KEY = (
        "collector_credential_recovery_pending_protected_v1"
    )

    def get_pending_credential_recovery(self):
        """Return the protected pending recovery, if one exists."""

        conn = self._connect()
        try:
            recovery_row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_RECOVERY_ID_KEY,),
            ).fetchone()
            credential_row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_RECOVERY_CREDENTIAL_KEY,),
            ).fetchone()

            if recovery_row is None and credential_row is None:
                return None
            if recovery_row is None or credential_row is None:
                raise CredentialProtectionError(
                    "collector credential recovery state is incomplete"
                )

            return {
                "recovery_id": str(recovery_row["value"]),
                "credential": self._unprotect_credential_value(
                    str(credential_row["value"])
                ),
            }
        finally:
            conn.close()

    def begin_credential_recovery(
        self,
        recovery_id: str,
        credential: str,
    ) -> None:
        """Persist a protected recovery candidate before the network call."""

        recovery_value = str(recovery_id or "").strip()
        if not recovery_value:
            raise ValueError("recovery_id must not be empty")

        encoded = self._protect_credential_value(credential)

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing_id = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_RECOVERY_ID_KEY,),
            ).fetchone()
            existing_credential = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_RECOVERY_CREDENTIAL_KEY,),
            ).fetchone()

            if existing_id is not None or existing_credential is not None:
                if existing_id is None or existing_credential is None:
                    conn.rollback()
                    raise CredentialProtectionError(
                        "collector credential recovery state is incomplete"
                    )

                existing_recovery = str(existing_id["value"])
                existing_value = self._unprotect_credential_value(
                    str(existing_credential["value"])
                )
                if (
                    existing_recovery != recovery_value
                    or existing_value != str(credential)
                ):
                    conn.rollback()
                    raise CredentialProtectionError(
                        "another collector credential recovery is pending"
                    )
                conn.commit()
                return

            conn.execute(
                "INSERT INTO collector_state(key, value) VALUES (?, ?)",
                (
                    self._PENDING_RECOVERY_ID_KEY,
                    recovery_value,
                ),
            )
            conn.execute(
                "INSERT INTO collector_state(key, value) VALUES (?, ?)",
                (
                    self._PENDING_RECOVERY_CREDENTIAL_KEY,
                    encoded,
                ),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def commit_credential_recovery(self, recovery_id: str) -> None:
        """Promote recovered credential and invalidate stale rotation state."""

        recovery_value = str(recovery_id or "").strip()
        if not recovery_value:
            raise ValueError("recovery_id must not be empty")

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            recovery_row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_RECOVERY_ID_KEY,),
            ).fetchone()
            credential_row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_RECOVERY_CREDENTIAL_KEY,),
            ).fetchone()

            if recovery_row is None or credential_row is None:
                conn.rollback()
                raise CredentialProtectionError(
                    "no complete collector credential recovery is pending"
                )

            if str(recovery_row["value"]) != recovery_value:
                conn.rollback()
                raise CredentialProtectionError(
                    "pending collector credential recovery_id mismatch"
                )

            self._unprotect_credential_value(
                str(credential_row["value"])
            )

            conn.execute(
                """
                INSERT INTO collector_state(key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (
                    self._PROTECTED_CREDENTIAL_KEY,
                    str(credential_row["value"]),
                ),
            )
            conn.execute(
                "DELETE FROM collector_state WHERE key = ?",
                (self._LEGACY_CREDENTIAL_KEY,),
            )
            conn.execute(
                "DELETE FROM collector_state WHERE key IN (?, ?, ?, ?)",
                (
                    self._PENDING_RECOVERY_ID_KEY,
                    self._PENDING_RECOVERY_CREDENTIAL_KEY,
                    self._PENDING_ROTATION_ID_KEY,
                    self._PENDING_ROTATION_CREDENTIAL_KEY,
                ),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    _PENDING_ROTATION_ID_KEY = "collector_credential_rotation_pending_id"
    _PENDING_ROTATION_CREDENTIAL_KEY = (
        "collector_credential_rotation_pending_protected_v1"
    )

    def get_pending_credential_rotation(self):
        """Return the protected pending rotation, if one exists."""

        conn = self._connect()
        try:
            rotation_row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_ROTATION_ID_KEY,),
            ).fetchone()
            credential_row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_ROTATION_CREDENTIAL_KEY,),
            ).fetchone()

            if rotation_row is None and credential_row is None:
                return None
            if rotation_row is None or credential_row is None:
                raise CredentialProtectionError(
                    "collector credential rotation state is incomplete"
                )

            return {
                "rotation_id": str(rotation_row["value"]),
                "credential": self._unprotect_credential_value(
                    str(credential_row["value"])
                ),
            }
        finally:
            conn.close()

    def begin_credential_rotation(
        self,
        rotation_id: str,
        credential: str,
    ) -> None:
        """Persist a protected candidate before any rotation network call."""

        rotation_value = str(rotation_id or "").strip()
        if not rotation_value:
            raise ValueError("rotation_id must not be empty")

        encoded = self._protect_credential_value(credential)

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing_id = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_ROTATION_ID_KEY,),
            ).fetchone()
            existing_credential = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_ROTATION_CREDENTIAL_KEY,),
            ).fetchone()

            if existing_id is not None or existing_credential is not None:
                if existing_id is None or existing_credential is None:
                    conn.rollback()
                    raise CredentialProtectionError(
                        "collector credential rotation state is incomplete"
                    )

                existing_rotation = str(existing_id["value"])
                existing_value = self._unprotect_credential_value(
                    str(existing_credential["value"])
                )
                if (
                    existing_rotation != rotation_value
                    or existing_value != str(credential)
                ):
                    conn.rollback()
                    raise CredentialProtectionError(
                        "another collector credential rotation is pending"
                    )
                conn.commit()
                return

            conn.execute(
                "INSERT INTO collector_state(key, value) VALUES (?, ?)",
                (
                    self._PENDING_ROTATION_ID_KEY,
                    rotation_value,
                ),
            )
            conn.execute(
                "INSERT INTO collector_state(key, value) VALUES (?, ?)",
                (
                    self._PENDING_ROTATION_CREDENTIAL_KEY,
                    encoded,
                ),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def commit_credential_rotation(self, rotation_id: str) -> None:
        """Atomically promote the protected pending credential to current."""

        rotation_value = str(rotation_id or "").strip()
        if not rotation_value:
            raise ValueError("rotation_id must not be empty")

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rotation_row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_ROTATION_ID_KEY,),
            ).fetchone()
            credential_row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_ROTATION_CREDENTIAL_KEY,),
            ).fetchone()

            if rotation_row is None or credential_row is None:
                conn.rollback()
                raise CredentialProtectionError(
                    "no complete collector credential rotation is pending"
                )

            if str(rotation_row["value"]) != rotation_value:
                conn.rollback()
                raise CredentialProtectionError(
                    "pending collector credential rotation_id mismatch"
                )

            self._unprotect_credential_value(
                str(credential_row["value"])
            )

            conn.execute(
                """
                INSERT INTO collector_state(key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (
                    self._PROTECTED_CREDENTIAL_KEY,
                    str(credential_row["value"]),
                ),
            )
            conn.execute(
                "DELETE FROM collector_state WHERE key = ?",
                (self._LEGACY_CREDENTIAL_KEY,),
            )
            conn.execute(
                "DELETE FROM collector_state WHERE key IN (?, ?)",
                (
                    self._PENDING_ROTATION_ID_KEY,
                    self._PENDING_ROTATION_CREDENTIAL_KEY,
                ),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    _ACTIVE_CLIENT_CERTIFICATE_REF_KEY = (
        "collector_active_client_certificate_ref_v1"
    )
    _PENDING_CLIENT_CERTIFICATE_ROTATION_KEY = (
        "collector_pending_client_certificate_rotation_v1"
    )

    @staticmethod
    def _client_certificate_reference(client_cert):
        if isinstance(client_cert, (tuple, list)):
            if len(client_cert) != 2:
                raise ValueError(
                    "client certificate tuple must contain certificate and key paths"
                )
            certificate = str(client_cert[0] or "").strip()
            key = str(client_cert[1] or "").strip()
            if not certificate or not key:
                raise ValueError(
                    "client certificate and key paths must not be empty"
                )
            return {"certificate": certificate, "key": key}

        certificate = str(client_cert or "").strip()
        if not certificate:
            raise ValueError("client certificate path must not be empty")
        return {"certificate": certificate, "key": None}

    @staticmethod
    def _client_certificate_from_reference(reference):
        certificate = str(reference.get("certificate") or "").strip()
        key = str(reference.get("key") or "").strip()
        if not certificate:
            raise ValueError("client certificate reference is incomplete")
        return (certificate, key) if key else certificate

    def get_active_client_certificate_reference(self):
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._ACTIVE_CLIENT_CERTIFICATE_REF_KEY,),
            ).fetchone()
            if row is None:
                return None
            return self._client_certificate_from_reference(
                json.loads(str(row["value"]))
            )
        finally:
            conn.close()

    def get_pending_client_certificate_rotation(self):
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_CLIENT_CERTIFICATE_ROTATION_KEY,),
            ).fetchone()
            if row is None:
                return None

            value = json.loads(str(row["value"]))
            return {
                "rotation_id": str(value["rotation_id"]),
                "fingerprint": str(value["fingerprint"]),
                "staged": bool(value.get("staged", False)),
                "client_cert": self._client_certificate_from_reference(
                    value["client_cert"]
                ),
            }
        finally:
            conn.close()

    def begin_client_certificate_rotation(
        self,
        rotation_id: str,
        client_cert,
        fingerprint: str,
    ) -> None:
        rotation_value = str(rotation_id or "").strip()
        fingerprint_value = str(fingerprint or "").strip().lower()
        if not rotation_value:
            raise ValueError("certificate rotation_id must not be empty")
        if not fingerprint_value:
            raise ValueError("certificate fingerprint must not be empty")

        value = {
            "rotation_id": rotation_value,
            "fingerprint": fingerprint_value,
            "staged": False,
            "client_cert": self._client_certificate_reference(client_cert),
        }

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_CLIENT_CERTIFICATE_ROTATION_KEY,),
            ).fetchone()

            if row is not None:
                existing = json.loads(str(row["value"]))
                if existing != value:
                    conn.rollback()
                    raise ValueError(
                        "another client certificate rotation is pending"
                    )
                conn.commit()
                return

            conn.execute(
                "INSERT INTO collector_state(key, value) VALUES (?, ?)",
                (
                    self._PENDING_CLIENT_CERTIFICATE_ROTATION_KEY,
                    json.dumps(
                        value,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def mark_client_certificate_rotation_staged(
        self,
        rotation_id: str,
    ) -> None:
        rotation_value = str(rotation_id or "").strip()
        if not rotation_value:
            raise ValueError("certificate rotation_id must not be empty")

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_CLIENT_CERTIFICATE_ROTATION_KEY,),
            ).fetchone()
            if row is None:
                conn.rollback()
                raise ValueError(
                    "no client certificate rotation is pending"
                )

            value = json.loads(str(row["value"]))
            if str(value.get("rotation_id") or "") != rotation_value:
                conn.rollback()
                raise ValueError(
                    "pending client certificate rotation_id mismatch"
                )

            value["staged"] = True
            conn.execute(
                "UPDATE collector_state SET value = ? WHERE key = ?",
                (
                    json.dumps(
                        value,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    self._PENDING_CLIENT_CERTIFICATE_ROTATION_KEY,
                ),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def complete_client_certificate_rotation(
        self,
        rotation_id: str,
    ) -> None:
        rotation_value = str(rotation_id or "").strip()
        if not rotation_value:
            raise ValueError("certificate rotation_id must not be empty")

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?",
                (self._PENDING_CLIENT_CERTIFICATE_ROTATION_KEY,),
            ).fetchone()
            if row is None:
                conn.commit()
                return

            value = json.loads(str(row["value"]))
            if str(value.get("rotation_id") or "") != rotation_value:
                conn.rollback()
                raise ValueError(
                    "pending client certificate rotation_id mismatch"
                )
            if not bool(value.get("staged", False)):
                conn.rollback()
                raise ValueError(
                    "client certificate rotation is not staged"
                )

            conn.execute(
                """
                INSERT INTO collector_state(key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (
                    self._ACTIVE_CLIENT_CERTIFICATE_REF_KEY,
                    json.dumps(
                        value["client_cert"],
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
            conn.execute(
                "DELETE FROM collector_state WHERE key = ?",
                (self._PENDING_CLIENT_CERTIFICATE_ROTATION_KEY,),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def get_checkpoint(self) -> Optional[int]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key='last_acked_record_id'"
            ).fetchone()
            return int(row["value"]) if row else None
        finally:
            conn.close()

    def initialize_checkpoint(self, record_id: int) -> int:
        """Persist the first collection baseline without moving it later."""

        checkpoint = int(record_id)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key='last_acked_record_id'"
            ).fetchone()
            if row is not None:
                conn.commit()
                return int(row["value"])

            conn.execute(
                "INSERT INTO collector_state(key, value) VALUES (?, ?)",
                ("last_acked_record_id", str(checkpoint)),
            )
            conn.commit()
            return checkpoint
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_collection_cursor(self) -> Optional[int]:
        """Return the highest RecordID durably owned by this collector."""

        conn = self._connect()
        try:
            checkpoint_row = conn.execute(
                "SELECT value FROM collector_state WHERE key='last_acked_record_id'"
            ).fetchone()
            pending_row = conn.execute(
                "SELECT MAX(max_record_id) AS max_record_id FROM outbound_batches"
            ).fetchone()

            values = []
            if checkpoint_row is not None:
                values.append(int(checkpoint_row["value"]))
            if pending_row is not None and pending_row["max_record_id"] is not None:
                values.append(int(pending_row["max_record_id"]))
            return max(values) if values else None
        finally:
            conn.close()

    def enqueue(self, payload: Dict[str, Any], max_record_id: Optional[int]) -> str:
        batch_id = str(payload.get("batch_id") or "").strip()
        if not batch_id:
            raise ValueError("payload batch_id is required")

        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO outbound_batches(
                    batch_id, payload_json, max_record_id
                ) VALUES (?, ?, ?)
                """,
                (batch_id, body, max_record_id),
            )
            conn.commit()
            return batch_id
        finally:
            conn.close()

    def pending(self, limit: int = 20) -> List[Dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT batch_id, payload_json, max_record_id, attempts,
                       last_error, created_at, last_attempt_at, next_attempt_at
                FROM outbound_batches
                ORDER BY
                    CASE WHEN max_record_id IS NULL THEN 1 ELSE 0 END,
                    max_record_id,
                    created_at,
                    batch_id
                LIMIT ?
                """,
                (int(limit),),
            ).fetchall()
            return [
                {
                    "batch_id": row["batch_id"],
                    "payload": json.loads(row["payload_json"]),
                    "max_record_id": row["max_record_id"],
                    "attempts": row["attempts"],
                    "last_error": row["last_error"],
                    "created_at": row["created_at"],
                    "last_attempt_at": row["last_attempt_at"],
                    "next_attempt_at": row["next_attempt_at"],
                }
                for row in rows
            ]
        finally:
            conn.close()

    def mark_attempt(
        self,
        batch_id: str,
        error: Optional[str] = None,
        attempted_at: Optional[float] = None,
        next_attempt_at: Optional[float] = None,
    ) -> None:
        attempt_time = time.time() if attempted_at is None else float(attempted_at)
        next_time = (
            None
            if next_attempt_at is None
            else float(next_attempt_at)
        )

        conn = self._connect()
        try:
            conn.execute(
                """
                UPDATE outbound_batches
                SET attempts = attempts + 1,
                    last_error = ?,
                    last_attempt_at = ?,
                    next_attempt_at = ?
                WHERE batch_id = ?
                """,
                (error, attempt_time, next_time, batch_id),
            )
            conn.commit()
        finally:
            conn.close()

    def acknowledge(
        self,
        batch_id: str,
        acknowledged_at: Optional[float] = None,
    ) -> None:
        ack_time = time.time() if acknowledged_at is None else float(acknowledged_at)

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT max_record_id FROM outbound_batches WHERE batch_id = ?",
                (batch_id,),
            ).fetchone()
            if not row:
                conn.rollback()
                return

            max_record_id = row["max_record_id"]
            if max_record_id is not None:
                existing = conn.execute(
                    "SELECT value FROM collector_state WHERE key='last_acked_record_id'"
                ).fetchone()
                current = int(existing["value"]) if existing else None
                checkpoint = int(max_record_id)
                if current is not None:
                    checkpoint = max(current, checkpoint)

                conn.execute(
                    """
                    INSERT INTO collector_state(key, value)
                    VALUES ('last_acked_record_id', ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value
                    """,
                    (str(checkpoint),),
                )

            conn.execute(
                """
                INSERT INTO collector_state(key, value)
                VALUES ('last_successful_ack_at', ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (str(ack_time),),
            )
            conn.execute(
                "DELETE FROM outbound_batches WHERE batch_id = ?",
                (batch_id,),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def transport_health(self, now: Optional[float] = None) -> Dict[str, Any]:
        """Return a durable collector transport-health snapshot."""

        now_value = time.time() if now is None else float(now)
        conn = self._connect()
        try:
            state_rows = {
                str(row["key"]): str(row["value"])
                for row in conn.execute(
                    """
                    SELECT key, value
                    FROM collector_state
                    WHERE key IN (
                        'collector_id',
                        'last_acked_record_id',
                        'last_successful_ack_at'
                    )
                    """
                ).fetchall()
            }

            summary = conn.execute(
                """
                SELECT
                    COUNT(*) AS pending_batches,
                    MIN(strftime('%s', created_at)) AS oldest_created_epoch,
                    MAX(max_record_id) AS highest_pending_record_id,
                    SUM(attempts) AS total_attempts
                FROM outbound_batches
                """
            ).fetchone()

            oldest = conn.execute(
                """
                SELECT batch_id, attempts, last_error,
                       last_attempt_at, next_attempt_at
                FROM outbound_batches
                ORDER BY
                    CASE WHEN max_record_id IS NULL THEN 1 ELSE 0 END,
                    max_record_id,
                    created_at,
                    batch_id
                LIMIT 1
                """
            ).fetchone()
        finally:
            conn.close()

        pending_batches = int(summary["pending_batches"] or 0)
        checkpoint = (
            int(state_rows["last_acked_record_id"])
            if "last_acked_record_id" in state_rows
            else None
        )
        highest_pending = summary["highest_pending_record_id"]

        cursor_values = []
        if checkpoint is not None:
            cursor_values.append(checkpoint)
        if highest_pending is not None:
            cursor_values.append(int(highest_pending))
        collection_cursor = max(cursor_values) if cursor_values else None

        oldest_created = summary["oldest_created_epoch"]
        oldest_age = None
        if oldest_created is not None:
            oldest_age = max(0.0, now_value - float(oldest_created))

        next_attempt_at = (
            float(oldest["next_attempt_at"])
            if oldest is not None and oldest["next_attempt_at"] is not None
            else None
        )
        retry_in = (
            max(0.0, next_attempt_at - now_value)
            if next_attempt_at is not None
            else None
        )
        last_error = (
            str(oldest["last_error"])
            if oldest is not None and oldest["last_error"] not in (None, "")
            else None
        )

        if pending_batches == 0:
            status = "HEALTHY"
        elif next_attempt_at is not None and next_attempt_at > now_value:
            status = "RETRY_WAIT"
        elif last_error:
            status = "DEGRADED"
        else:
            status = "BACKLOG"

        return {
            "status": status,
            "collector_id": state_rows.get("collector_id"),
            "checkpoint": checkpoint,
            "collection_cursor": collection_cursor,
            "pending_batches": pending_batches,
            "oldest_pending_age_seconds": (
                round(oldest_age, 3) if oldest_age is not None else None
            ),
            "oldest_pending_batch_id": (
                str(oldest["batch_id"]) if oldest is not None else None
            ),
            "oldest_pending_attempts": (
                int(oldest["attempts"]) if oldest is not None else 0
            ),
            "total_attempts": int(summary["total_attempts"] or 0),
            "last_error": last_error,
            "last_attempt_at": (
                float(oldest["last_attempt_at"])
                if oldest is not None and oldest["last_attempt_at"] is not None
                else None
            ),
            "next_attempt_at": next_attempt_at,
            "retry_in_seconds": (
                round(retry_in, 3) if retry_in is not None else None
            ),
            "last_successful_ack_at": (
                float(state_rows["last_successful_ack_at"])
                if "last_successful_ack_at" in state_rows
                else None
            ),
        }
