"""Read-only enterprise collector and asset inventory.

Security identity remains authoritative in the server-side collector registry.
Collector-reported operational telemetry is exposed separately and is never
promoted into trust state.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone


DEFAULT_COLLECTOR_STALE_AFTER_SECONDS = 90.0


class CollectorInventoryNotFound(LookupError):
    """Raised when a requested collector does not exist."""


def _normalize_stale_after_seconds(value):
    try:
        threshold = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "stale_after_seconds must be numeric"
        ) from exc

    if (
        not math.isfinite(threshold)
        or threshold <= 0
    ):
        raise ValueError(
            "stale_after_seconds must be greater than zero"
        )

    return threshold


def _utc_now(value=None):
    if value is None:
        return datetime.now(timezone.utc)

    if isinstance(value, datetime):
        result = value
    else:
        raise ValueError(
            "now must be a datetime"
        )

    if result.tzinfo is None:
        return result.replace(
            tzinfo=timezone.utc
        )

    return result.astimezone(
        timezone.utc
    )


def _parse_server_timestamp(value):
    if value in (None, ""):
        return None

    normalized = str(value).strip()

    if not normalized:
        return None

    if normalized.endswith("Z"):
        normalized = (
            normalized[:-1]
            + "+00:00"
        )

    try:
        parsed = datetime.fromisoformat(
            normalized
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed.astimezone(
        timezone.utc
    )


def _liveness_state(
    *,
    status,
    revoked_at,
    last_seen_at,
    last_heartbeat_at,
    now,
    stale_after_seconds,
):
    threshold = _normalize_stale_after_seconds(
        stale_after_seconds
    )

    current_time = _utc_now(now)

    candidates = []

    seen = _parse_server_timestamp(
        last_seen_at
    )

    if seen is not None:
        candidates.append((
            seen,
            last_seen_at,
            "authenticated_activity",
        ))

    heartbeat = _parse_server_timestamp(
        last_heartbeat_at
    )

    if heartbeat is not None:
        candidates.append((
            heartbeat,
            last_heartbeat_at,
            "heartbeat",
        ))

    latest = (
        max(candidates, key=lambda item: item[0])
        if candidates
        else None
    )

    if latest is None:
        last_contact_at = None
        last_contact_source = None
        age_seconds = None
    else:
        timestamp, raw_value, source = latest

        age_seconds = max(
            0.0,
            (
                current_time - timestamp
            ).total_seconds(),
        )

        age_seconds = round(
            age_seconds,
            3,
        )

        last_contact_at = raw_value
        last_contact_source = source

    if (
        str(status or "").upper()
        == "REVOKED"
        or revoked_at not in (None, "")
    ):
        state = "REVOKED"
    elif latest is None:
        state = "NEVER_SEEN"
    elif age_seconds <= threshold:
        state = "CURRENT"
    else:
        state = "STALE"

    return {
        "authority": "server_derived",
        "state": state,
        "last_contact_at": last_contact_at,
        "last_contact_source": (
            last_contact_source
        ),
        "age_seconds": age_seconds,
        "stale_after_seconds": threshold,
    }


def _queue_summary(conn, collector_id):
    counts = {
        "queued": 0,
        "processing": 0,
        "processed": 0,
        "failed": 0,
    }

    rows = conn.execute(
        """
        SELECT state, COUNT(*)
        FROM collector_ingest_batches
        WHERE collector_id = ?
        GROUP BY state
        """,
        (collector_id,),
    ).fetchall()

    for row in rows:
        state = str(row[0] or "").lower()

        if state in counts:
            counts[state] = int(row[1] or 0)

    counts["total"] = sum(
        counts.values()
    )

    return counts


def _assets_for_collector(
    conn,
    collector_id,
):
    rows = conn.execute(
        """
        SELECT asset_id,
               hostname,
               os,
               primary_ip,
               first_seen_at,
               last_seen_at
        FROM assets
        WHERE collector_id = ?
        ORDER BY hostname ASC, asset_id ASC
        """,
        (collector_id,),
    ).fetchall()

    return [
        {
            "asset_id": row[0],
            "hostname": row[1],
            "os": row[2],
            "primary_ip": row[3],
            "first_seen_at": row[4],
            "last_seen_at": row[5],
        }
        for row in rows
    ]


def _credential_state(
    *,
    status,
    revoked_at,
    credential_fingerprint,
):
    if (
        status == "REVOKED"
        or revoked_at not in (None, "")
    ):
        return "REVOKED"

    if credential_fingerprint:
        return "ENROLLED"

    return "MISSING"


def _certificate_state(
    *,
    status,
    revoked_at,
    certificate_fingerprint,
    pending_certificate_fingerprint,
):
    if (
        status == "REVOKED"
        or revoked_at not in (None, "")
    ):
        return "REVOKED"

    if pending_certificate_fingerprint:
        return "ROTATION_PENDING"

    if certificate_fingerprint:
        return "BOUND"

    return "UNBOUND"


def _collector_row(
    conn,
    collector_id=None,
):
    where = ""
    params = ()

    if collector_id is not None:
        where = "WHERE collector_id = ?"
        params = (collector_id,)

    return conn.execute(
        f"""
        SELECT collector_id,
               hostname,
               display_name,
               version,
               status,
               credential_fingerprint,
               enrolled_at,
               last_seen_at,
               revoked_at,
               credential_rotated_at,
               credential_recovered_at,
               certificate_fingerprint,
               certificate_bound_at,
               pending_certificate_fingerprint,
               certificate_rotation_started_at,
               certificate_rotated_at,
               last_heartbeat_at,
               heartbeat_peer_ip,
               heartbeat_credential_authenticated,
               heartbeat_mtls_required,
               heartbeat_mtls_verified,
               reported_version,
               reported_transport_status,
               reported_pending_batches,
               reported_checkpoint,
               reported_collection_cursor,
               reported_retry_in_seconds,
               reported_last_successful_ack_at,
               reported_certificate_rotation_pending
        FROM collectors
        {where}
        ORDER BY hostname ASC, collector_id ASC
        """,
        params,
    ).fetchall()


def _serialize_collector(
    conn,
    row,
    *,
    now=None,
    stale_after_seconds=DEFAULT_COLLECTOR_STALE_AFTER_SECONDS,
):
    collector_id = str(row[0])
    status = str(
        row[4] or ""
    ).upper()

    revoked_at = row[8]

    credential_state = _credential_state(
        status=status,
        revoked_at=revoked_at,
        credential_fingerprint=row[5],
    )

    certificate_state = _certificate_state(
        status=status,
        revoked_at=revoked_at,
        certificate_fingerprint=row[11],
        pending_certificate_fingerprint=row[13],
    )

    return {
        "identity": {
            "collector_id": collector_id,
            "hostname": row[1],
            "display_name": row[2],
            "status": status,
            "enrolled_at": row[6],
            "revoked_at": revoked_at,
        },
        "security": {
            "authority": "server",
            "credential_state": credential_state,
            "credential_rotated_at": row[9],
            "credential_recovered_at": row[10],
            "certificate_state": certificate_state,
            "certificate_bound_at": row[12],
            "certificate_rotation_started_at": row[14],
            "certificate_rotated_at": row[15],
        },
        "liveness": _liveness_state(
            status=status,
            revoked_at=revoked_at,
            last_seen_at=row[7],
            last_heartbeat_at=row[16],
            now=now,
            stale_after_seconds=stale_after_seconds,
        ),
        "server_observed": {
            "authority": "server",
            "last_seen_at": row[7],
            "last_heartbeat_at": row[16],
            "peer_ip": row[17],
            "credential_authenticated": bool(
                row[18]
            ),
            "mtls_required": bool(
                row[19]
            ),
            "mtls_verified": bool(
                row[20]
            ),
        },
        "collector_reported": {
            "authority": (
                "collector_reported_operational_only"
            ),
            "registered_version": row[3],
            "reported_version": row[21],
            "transport_status": row[22],
            "pending_batches": row[23],
            "checkpoint": row[24],
            "collection_cursor": row[25],
            "retry_in_seconds": row[26],
            "last_successful_ack_at": row[27],
            "certificate_rotation_pending": (
                None
                if row[28] is None
                else bool(row[28])
            ),
        },
        "server_queue": _queue_summary(
            conn,
            collector_id,
        ),
        "assets": _assets_for_collector(
            conn,
            collector_id,
        ),
    }


def list_collector_inventory(
    conn,
    *,
    now=None,
    stale_after_seconds=DEFAULT_COLLECTOR_STALE_AFTER_SECONDS,
):
    """Return all registered collectors in deterministic order."""

    _normalize_stale_after_seconds(
        stale_after_seconds
    )

    return [
        _serialize_collector(
            conn,
            row,
            now=now,
            stale_after_seconds=stale_after_seconds,
        )
        for row in _collector_row(conn)
    ]


def get_collector_inventory(
    conn,
    collector_id,
    *,
    now=None,
    stale_after_seconds=DEFAULT_COLLECTOR_STALE_AFTER_SECONDS,
):
    """Return one collector without exposing stored security material."""

    normalized = str(
        collector_id or ""
    ).strip()

    if not normalized:
        raise CollectorInventoryNotFound(
            "collector not found"
        )

    rows = _collector_row(
        conn,
        normalized,
    )

    if not rows:
        raise CollectorInventoryNotFound(
            "collector not found"
        )

    _normalize_stale_after_seconds(
        stale_after_seconds
    )

    return _serialize_collector(
        conn,
        rows[0],
        now=now,
        stale_after_seconds=stale_after_seconds,
    )
