"""Human-user authentication and persistent session primitives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional


VALID_ROLES = {
    "ADMINISTRATOR",
    "ANALYST",
    "VIEWER",
}

_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_PASSWORD_PREFIX = "scrypt"
_MIN_PASSWORD_LENGTH = 12
_MAX_PASSWORD_LENGTH = 1024
_MAX_USERNAME_LENGTH = 128
_MAX_USER_AGENT_LENGTH = 512
_CSRF_CONTEXT = b"aegisguard-csrf-v1"


class UserAuthError(ValueError):
    """Base error for user/session authentication operations."""


class UserValidationError(UserAuthError):
    """Raised when user input is structurally invalid."""


class UserAlreadyExistsError(UserAuthError):
    """Raised when a normalized username already exists."""


class UserAuthenticationError(UserAuthError):
    """Raised when username/password authentication fails."""


class SessionAuthenticationError(UserAuthError):
    """Raised when a session token is missing, invalid, expired, or revoked."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_timestamp(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise SessionAuthenticationError("session timestamp is missing")
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_username(username: str) -> str:
    value = str(username or "").strip().lower()
    if not value:
        raise UserValidationError("username is required")
    if len(value) > _MAX_USERNAME_LENGTH:
        raise UserValidationError(
            f"username must be at most {_MAX_USERNAME_LENGTH} characters"
        )
    if any(char.isspace() for char in value):
        raise UserValidationError("username must not contain whitespace")
    return value


def normalize_role(role: str) -> str:
    value = str(role or "").strip().upper()
    if value not in VALID_ROLES:
        raise UserValidationError(
            "role must be ADMINISTRATOR, ANALYST, or VIEWER"
        )
    return value


def validate_password(password: str) -> str:
    value = str(password or "")
    if len(value) < _MIN_PASSWORD_LENGTH:
        raise UserValidationError(
            f"password must be at least {_MIN_PASSWORD_LENGTH} characters"
        )
    if len(value) > _MAX_PASSWORD_LENGTH:
        raise UserValidationError(
            f"password must be at most {_MAX_PASSWORD_LENGTH} characters"
        )
    return value


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def hash_password(password: str, *, salt: Optional[bytes] = None) -> str:
    password_value = validate_password(password)
    salt_value = secrets.token_bytes(16) if salt is None else bytes(salt)
    if len(salt_value) < 16:
        raise UserValidationError("password salt must be at least 16 bytes")

    digest = hashlib.scrypt(
        password_value.encode("utf-8"),
        salt=salt_value,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return "$".join(
        (
            _PASSWORD_PREFIX,
            str(_SCRYPT_N),
            str(_SCRYPT_R),
            str(_SCRYPT_P),
            _b64_encode(salt_value),
            _b64_encode(digest),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        parts = str(encoded or "").split("$")
        if len(parts) != 6 or parts[0] != _PASSWORD_PREFIX:
            return False

        n_value = int(parts[1])
        r_value = int(parts[2])
        p_value = int(parts[3])

        if (
            n_value != _SCRYPT_N
            or r_value != _SCRYPT_R
            or p_value != _SCRYPT_P
        ):
            return False

        salt = _b64_decode(parts[4])
        expected = _b64_decode(parts[5])
        if len(expected) != _SCRYPT_DKLEN:
            return False

        candidate = hashlib.scrypt(
            str(password or "").encode("utf-8"),
            salt=salt,
            n=n_value,
            r=r_value,
            p=p_value,
            dklen=len(expected),
        )
        return hmac.compare_digest(candidate, expected)
    except (ValueError, TypeError):
        return False


def session_token_fingerprint(token: str) -> str:
    value = str(token or "").strip()
    if not value:
        raise SessionAuthenticationError("session token is required")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def csrf_token_for_session_token(token: str) -> str:
    value = str(token or "").strip()
    if not value:
        raise SessionAuthenticationError("session token is required")
    digest = hmac.new(
        value.encode("utf-8"),
        _CSRF_CONTEXT,
        hashlib.sha256,
    ).digest()
    return _b64_encode(digest)


def verify_session_csrf(token: str, csrf_token: str) -> bool:
    provided = str(csrf_token or "").strip()
    if not provided:
        return False
    try:
        expected = csrf_token_for_session_token(token)
    except SessionAuthenticationError:
        return False
    return hmac.compare_digest(provided, expected)


def create_user(
    conn,
    username: str,
    password: str,
    role: str,
    *,
    user_id: Optional[str] = None,
):
    username_value = normalize_username(username)
    role_value = normalize_role(role)
    password_hash = hash_password(password)
    user_id_value = str(user_id or uuid.uuid4()).strip()
    if not user_id_value:
        raise UserValidationError("user_id is required")

    try:
        conn.execute(
            """
            INSERT INTO users(
                user_id,
                username,
                password_hash,
                role,
                active
            ) VALUES (?, ?, ?, ?, 1)
            """,
            (
                user_id_value,
                username_value,
                password_hash,
                role_value,
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise UserAlreadyExistsError(
            "username already exists"
        ) from exc

    return {
        "user_id": user_id_value,
        "username": username_value,
        "role": role_value,
        "active": True,
    }


def set_user_active(conn, user_id: str, active: bool) -> bool:
    cursor = conn.execute(
        """
        UPDATE users
        SET active = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ?
        """,
        (1 if active else 0, str(user_id or "").strip()),
    )
    conn.commit()
    return cursor.rowcount == 1


def authenticate_user(conn, username: str, password: str):
    try:
        username_value = normalize_username(username)
    except UserValidationError as exc:
        raise UserAuthenticationError(
            "invalid username or password"
        ) from exc

    row = conn.execute(
        """
        SELECT user_id,
               username,
               password_hash,
               role,
               active
        FROM users
        WHERE username = ?
        """,
        (username_value,),
    ).fetchone()

    if row is None:
        dummy_password = str(password or "")
        if len(dummy_password) < _MIN_PASSWORD_LENGTH:
            dummy_password = "invalid-password-value"
        hash_password(
            dummy_password,
            salt=b"\x00" * 16,
        )
        raise UserAuthenticationError("invalid username or password")

    if not bool(row[4]):
        raise UserAuthenticationError("invalid username or password")

    if not verify_password(password, row[2]):
        raise UserAuthenticationError("invalid username or password")

    return {
        "user_id": str(row[0]),
        "username": str(row[1]),
        "role": str(row[3]),
        "active": True,
    }


def create_session(
    conn,
    user_id: str,
    *,
    ttl_seconds: int,
    peer_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    now: Optional[datetime] = None,
    token_factory=None,
):
    ttl_value = int(ttl_seconds)
    if ttl_value <= 0:
        raise UserValidationError("session TTL must be greater than zero")

    now_value = _utc_now() if now is None else now.astimezone(timezone.utc)
    expires_at = now_value + timedelta(seconds=ttl_value)
    session_id = str(uuid.uuid4())

    factory = token_factory or (lambda: secrets.token_urlsafe(48))
    token = str(factory() or "").strip()
    if len(token) < 32:
        raise UserValidationError("generated session token is too short")

    token_hash = session_token_fingerprint(token)
    user_agent_value = str(user_agent or "")[:_MAX_USER_AGENT_LENGTH] or None
    peer_ip_value = str(peer_ip or "").strip() or None

    row = conn.execute(
        """
        SELECT active
        FROM users
        WHERE user_id = ?
        """,
        (str(user_id or "").strip(),),
    ).fetchone()
    if row is None or not bool(row[0]):
        raise UserAuthenticationError("user is not active")

    conn.execute(
        """
        INSERT INTO sessions(
            session_id,
            user_id,
            token_hash,
            created_at,
            last_seen_at,
            expires_at,
            peer_ip,
            user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            str(user_id),
            token_hash,
            _format_timestamp(now_value),
            _format_timestamp(now_value),
            _format_timestamp(expires_at),
            peer_ip_value,
            user_agent_value,
        ),
    )
    conn.commit()

    return {
        "session_id": session_id,
        "token": token,
        "csrf_token": csrf_token_for_session_token(token),
        "expires_at": _format_timestamp(expires_at),
    }


def authenticate_session(
    conn,
    token: str,
    *,
    now: Optional[datetime] = None,
    idle_timeout_seconds: Optional[int] = None,
):
    token_hash = session_token_fingerprint(token)
    row = conn.execute(
        """
        SELECT s.session_id,
               s.user_id,
               s.expires_at,
               s.last_seen_at,
               s.revoked_at,
               u.username,
               u.role,
               u.active
        FROM sessions AS s
        JOIN users AS u
          ON u.user_id = s.user_id
        WHERE s.token_hash = ?
        """,
        (token_hash,),
    ).fetchone()

    if row is None:
        raise SessionAuthenticationError("invalid session")

    if row[4] not in (None, ""):
        raise SessionAuthenticationError("session is revoked")

    if not bool(row[7]):
        raise SessionAuthenticationError("user is inactive")

    now_value = _utc_now() if now is None else now.astimezone(timezone.utc)
    expires_at = _parse_timestamp(row[2])
    if now_value >= expires_at:
        raise SessionAuthenticationError("session is expired")

    if idle_timeout_seconds is not None:
        idle_timeout = int(idle_timeout_seconds)
        if idle_timeout <= 0:
            raise UserValidationError(
                "session idle timeout must be greater than zero"
            )
        last_seen_at = _parse_timestamp(row[3])
        if now_value >= last_seen_at + timedelta(seconds=idle_timeout):
            raise SessionAuthenticationError("session idle timeout")

    conn.execute(
        """
        UPDATE sessions
        SET last_seen_at = ?
        WHERE session_id = ?
        """,
        (_format_timestamp(now_value), str(row[0])),
    )
    conn.commit()

    return {
        "session_id": str(row[0]),
        "user_id": str(row[1]),
        "username": str(row[5]),
        "role": str(row[6]),
        "active": True,
        "expires_at": _format_timestamp(expires_at),
    }


def revoke_session(
    conn,
    token: str,
    *,
    revoked_at: Optional[datetime] = None,
) -> bool:
    token_hash = session_token_fingerprint(token)
    when = _utc_now() if revoked_at is None else revoked_at.astimezone(
        timezone.utc
    )
    cursor = conn.execute(
        """
        UPDATE sessions
        SET revoked_at = ?
        WHERE token_hash = ?
          AND revoked_at IS NULL
        """,
        (_format_timestamp(when), token_hash),
    )
    conn.commit()
    return cursor.rowcount == 1
