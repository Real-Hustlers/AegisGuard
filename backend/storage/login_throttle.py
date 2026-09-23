"""Persistent login throttling for human application authentication."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


DEFAULT_LOGIN_FAILURE_LIMIT = 5
DEFAULT_LOGIN_WINDOW_SECONDS = 5 * 60
DEFAULT_LOGIN_BLOCK_SECONDS = 5 * 60


class LoginThrottledError(ValueError):
    """Raised when a username/peer login bucket is temporarily blocked."""


def _utc_now():
    return datetime.now(timezone.utc)


def _format_timestamp(value):
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_timestamp(value):
    text = str(value or "").strip()
    if not text:
        return None
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _bucket(username, peer_ip):
    username_value = str(username or "").strip().lower() or "<empty>"
    peer_value = str(peer_ip or "").strip() or "<unknown>"
    return username_value[:128], peer_value[:128]


def check_login_allowed(conn, username, peer_ip, *, now=None):
    """Raise LoginThrottledError when the persistent bucket is blocked."""

    username_value, peer_value = _bucket(username, peer_ip)
    row = conn.execute(
        """
        SELECT blocked_until
        FROM auth_login_throttle
        WHERE username = ?
          AND peer_ip = ?
        """,
        (username_value, peer_value),
    ).fetchone()

    if row is None:
        return

    blocked_until = _parse_timestamp(row[0])
    if blocked_until is None:
        return

    now_value = _utc_now() if now is None else now.astimezone(timezone.utc)
    if now_value < blocked_until:
        raise LoginThrottledError("too many login attempts")


def record_login_failure(
    conn,
    username,
    peer_ip,
    *,
    failure_limit=DEFAULT_LOGIN_FAILURE_LIMIT,
    window_seconds=DEFAULT_LOGIN_WINDOW_SECONDS,
    block_seconds=DEFAULT_LOGIN_BLOCK_SECONDS,
    now=None,
):
    """Record one failed authentication and return the updated throttle state."""

    limit = int(failure_limit)
    window = int(window_seconds)
    block = int(block_seconds)
    if limit <= 0 or window <= 0 or block <= 0:
        raise ValueError("login throttle values must be greater than zero")

    username_value, peer_value = _bucket(username, peer_ip)
    now_value = _utc_now() if now is None else now.astimezone(timezone.utc)

    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            """
            SELECT failure_count,
                   window_started_at,
                   blocked_until
            FROM auth_login_throttle
            WHERE username = ?
              AND peer_ip = ?
            """,
            (username_value, peer_value),
        ).fetchone()

        reset_bucket = True
        count = 0
        if row is not None:
            window_started = _parse_timestamp(row[1])
            blocked_until = _parse_timestamp(row[2])
            if blocked_until is not None and now_value < blocked_until:
                conn.commit()
                return {
                    "failure_count": int(row[0]),
                    "blocked_until": _format_timestamp(blocked_until),
                }
            if (
                window_started is not None
                and now_value
                < window_started + timedelta(seconds=window)
            ):
                reset_bucket = False
                count = int(row[0])

        if reset_bucket:
            count = 1
            window_started = now_value
        else:
            count += 1

        blocked_until = None
        if count >= limit:
            blocked_until = now_value + timedelta(seconds=block)

        conn.execute(
            """
            INSERT INTO auth_login_throttle(
                username,
                peer_ip,
                failure_count,
                window_started_at,
                blocked_until,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(username, peer_ip) DO UPDATE SET
                failure_count = excluded.failure_count,
                window_started_at = excluded.window_started_at,
                blocked_until = excluded.blocked_until,
                updated_at = excluded.updated_at
            """,
            (
                username_value,
                peer_value,
                count,
                _format_timestamp(window_started),
                (
                    _format_timestamp(blocked_until)
                    if blocked_until is not None
                    else None
                ),
                _format_timestamp(now_value),
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return {
        "failure_count": count,
        "blocked_until": (
            _format_timestamp(blocked_until)
            if blocked_until is not None
            else None
        ),
    }


def clear_login_failures(conn, username, peer_ip):
    username_value, peer_value = _bucket(username, peer_ip)
    conn.execute(
        """
        DELETE FROM auth_login_throttle
        WHERE username = ?
          AND peer_ip = ?
        """,
        (username_value, peer_value),
    )
    conn.commit()
