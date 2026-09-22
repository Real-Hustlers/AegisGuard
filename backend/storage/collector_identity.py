"""Collector identity, enrollment, authentication, and revocation primitives.

S3-1A intentionally contains no Flask/API behavior. It establishes one
authoritative server-side identity contract on top of the existing S1
``collectors`` table so later S3 slices can enforce authentication without
creating a parallel device registry.
"""

import hashlib
import hmac
import json
import secrets
from typing import Any, Callable, Dict, Optional


class CollectorIdentityError(ValueError):
    """Base error for collector identity operations."""


class CollectorEnrollmentError(CollectorIdentityError):
    """Raised when a collector cannot be enrolled."""


class CollectorAuthenticationError(CollectorIdentityError):
    """Raised when collector authentication fails."""


class CollectorRevokedError(CollectorAuthenticationError):
    """Raised when a revoked collector attempts authentication."""


class CollectorRotationError(CollectorIdentityError):
    """Raised when a collector credential rotation cannot be completed."""


class CollectorRotationConflictError(CollectorRotationError):
    """Raised when one rotation_id is reused with different credential data."""


def _require(value: str, field_name: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise CollectorIdentityError(f"{field_name} is required")
    return normalized


def credential_fingerprint(credential: str) -> str:
    """Return the SHA-256 fingerprint stored instead of the credential."""

    value = _require(credential, "credential")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _generate_credential() -> str:
    # 32 random bytes -> roughly 256 bits of entropy before URL-safe encoding.
    return secrets.token_urlsafe(32)


def enroll_collector(
    conn,
    collector_id: str,
    hostname: str,
    *,
    version: Optional[str] = None,
    display_name: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    credential_factory: Optional[Callable[[], str]] = None,
) -> Dict[str, Any]:
    """Enroll one collector and issue its credential exactly once.

    Only the SHA-256 fingerprint is persisted server-side. The plaintext
    credential is returned to the caller once and cannot be recovered from the
    database later.
    """

    collector_id = _require(collector_id, "collector_id")
    hostname = _require(hostname, "hostname")
    metadata_json = json.dumps(
        metadata or {},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )

    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            """
            SELECT collector_id, status, revoked_at
            FROM collectors
            WHERE collector_id = ?
            """,
            (collector_id,),
        ).fetchone()

        if existing is not None:
            conn.rollback()
            raise CollectorEnrollmentError(
                f"collector {collector_id} is already enrolled"
            )

        factory = credential_factory or _generate_credential
        credential = _require(factory(), "generated credential")
        fingerprint = credential_fingerprint(credential)

        conn.execute(
            """
            INSERT INTO collectors(
                collector_id,
                hostname,
                display_name,
                version,
                status,
                credential_fingerprint,
                metadata_json
            ) VALUES (?, ?, ?, ?, 'ENROLLED', ?, ?)
            """,
            (
                collector_id,
                hostname,
                display_name,
                version,
                fingerprint,
                metadata_json,
            ),
        )
        conn.commit()
    except CollectorIdentityError:
        raise
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise

    return {
        "collector_id": collector_id,
        "hostname": hostname,
        "status": "ENROLLED",
        "credential": credential,
        "credential_fingerprint": fingerprint,
    }


def authenticate_collector(
    conn,
    collector_id: str,
    credential: str,
    *,
    hostname: Optional[str] = None,
    seen_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Authenticate one enrolled collector and update its last-seen time."""

    collector_id = _require(collector_id, "collector_id")
    credential = _require(credential, "credential")

    row = conn.execute(
        """
        SELECT collector_id, hostname, display_name, version, status,
               credential_fingerprint, enrolled_at, last_seen_at, revoked_at
        FROM collectors
        WHERE collector_id = ?
        """,
        (collector_id,),
    ).fetchone()

    if row is None:
        raise CollectorAuthenticationError("unknown collector")

    status = str(row[4] or "").upper()
    revoked_at = row[8]
    if status == "REVOKED" or revoked_at not in (None, ""):
        raise CollectorRevokedError("collector is revoked")

    if status != "ENROLLED":
        raise CollectorAuthenticationError(
            f"collector status {status or 'EMPTY'} is not allowed"
        )

    stored_fingerprint = str(row[5] or "")
    presented_fingerprint = credential_fingerprint(credential)
    if (
        not stored_fingerprint
        or not hmac.compare_digest(
            stored_fingerprint,
            presented_fingerprint,
        )
    ):
        raise CollectorAuthenticationError("invalid collector credential")

    registered_hostname = str(row[1] or "")
    if hostname is not None:
        presented_hostname = _require(hostname, "hostname")
        if not hmac.compare_digest(registered_hostname, presented_hostname):
            raise CollectorAuthenticationError("collector hostname mismatch")

    if seen_at is None:
        conn.execute(
            """
            UPDATE collectors
            SET last_seen_at = CURRENT_TIMESTAMP
            WHERE collector_id = ?
            """,
            (collector_id,),
        )
    else:
        conn.execute(
            """
            UPDATE collectors
            SET last_seen_at = ?
            WHERE collector_id = ?
            """,
            (str(seen_at), collector_id),
        )
    conn.commit()

    refreshed = conn.execute(
        """
        SELECT last_seen_at
        FROM collectors
        WHERE collector_id = ?
        """,
        (collector_id,),
    ).fetchone()

    return {
        "collector_id": collector_id,
        "hostname": registered_hostname,
        "display_name": row[2],
        "version": row[3],
        "status": status,
        "enrolled_at": row[6],
        "last_seen_at": refreshed[0] if refreshed else row[7],
    }


def revoke_collector(
    conn,
    collector_id: str,
    *,
    revoked_at: Optional[str] = None,
) -> bool:
    """Revoke one collector so all later authentication fails closed."""

    collector_id = _require(collector_id, "collector_id")

    if revoked_at is None:
        cursor = conn.execute(
            """
            UPDATE collectors
            SET status = 'REVOKED',
                revoked_at = CURRENT_TIMESTAMP
            WHERE collector_id = ?
              AND status != 'REVOKED'
            """,
            (collector_id,),
        )
    else:
        cursor = conn.execute(
            """
            UPDATE collectors
            SET status = 'REVOKED',
                revoked_at = ?
            WHERE collector_id = ?
              AND status != 'REVOKED'
            """,
            (str(revoked_at), collector_id),
        )

    conn.commit()
    return cursor.rowcount == 1


def rotate_collector_credential(
    conn,
    collector_id: str,
    current_credential: str,
    new_credential: str,
    rotation_id: str,
    *,
    hostname: Optional[str] = None,
) -> Dict[str, Any]:
    """Atomically rotate one collector credential with idempotent replay."""

    collector_id = _require(collector_id, "collector_id")
    current_credential = _require(
        current_credential,
        "current credential",
    )
    new_credential = _require(new_credential, "new credential")
    rotation_id = _require(rotation_id, "rotation_id")

    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT hostname, status, credential_fingerprint, revoked_at,
                   credential_rotation_id, credential_rotated_at
            FROM collectors
            WHERE collector_id = ?
            """,
            (collector_id,),
        ).fetchone()

        if row is None:
            conn.rollback()
            raise CollectorAuthenticationError("unknown collector")

        registered_hostname = str(row[0] or "")
        status = str(row[1] or "").upper()
        stored_fingerprint = str(row[2] or "")
        revoked_at = row[3]
        stored_rotation_id = str(row[4] or "")

        if status == "REVOKED" or revoked_at not in (None, ""):
            conn.rollback()
            raise CollectorRevokedError("collector is revoked")

        if status != "ENROLLED":
            conn.rollback()
            raise CollectorAuthenticationError(
                f"collector status {status or 'EMPTY'} is not allowed"
            )

        if hostname is not None:
            presented_hostname = _require(hostname, "hostname")
            if not hmac.compare_digest(
                registered_hostname,
                presented_hostname,
            ):
                conn.rollback()
                raise CollectorAuthenticationError(
                    "collector hostname mismatch"
                )

        current_fingerprint = credential_fingerprint(
            current_credential
        )
        new_fingerprint = credential_fingerprint(new_credential)

        if stored_rotation_id == rotation_id:
            if not hmac.compare_digest(
                stored_fingerprint,
                new_fingerprint,
            ):
                conn.rollback()
                raise CollectorRotationConflictError(
                    "rotation_id was already used with different credential data"
                )

            if not hmac.compare_digest(
                stored_fingerprint,
                current_fingerprint,
            ):
                conn.rollback()
                raise CollectorAuthenticationError(
                    "invalid collector credential"
                )

            conn.execute(
                """
                UPDATE collectors
                SET last_seen_at = CURRENT_TIMESTAMP
                WHERE collector_id = ?
                """,
                (collector_id,),
            )
            conn.commit()
            return {
                "collector_id": collector_id,
                "hostname": registered_hostname,
                "status": status,
                "rotation_id": rotation_id,
                "rotated_at": row[5],
                "duplicate": True,
            }

        if (
            not stored_fingerprint
            or not hmac.compare_digest(
                stored_fingerprint,
                current_fingerprint,
            )
        ):
            conn.rollback()
            raise CollectorAuthenticationError(
                "invalid collector credential"
            )

        if hmac.compare_digest(
            stored_fingerprint,
            new_fingerprint,
        ):
            conn.rollback()
            raise CollectorRotationError(
                "new credential must differ from current credential"
            )

        conn.execute(
            """
            UPDATE collectors
            SET credential_fingerprint = ?,
                credential_rotation_id = ?,
                credential_rotated_at = CURRENT_TIMESTAMP,
                last_seen_at = CURRENT_TIMESTAMP
            WHERE collector_id = ?
            """,
            (
                new_fingerprint,
                rotation_id,
                collector_id,
            ),
        )
        conn.commit()

        refreshed = conn.execute(
            """
            SELECT credential_rotated_at
            FROM collectors
            WHERE collector_id = ?
            """,
            (collector_id,),
        ).fetchone()

        return {
            "collector_id": collector_id,
            "hostname": registered_hostname,
            "status": status,
            "rotation_id": rotation_id,
            "rotated_at": refreshed[0] if refreshed else None,
            "duplicate": False,
        }
    except CollectorIdentityError:
        raise
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
