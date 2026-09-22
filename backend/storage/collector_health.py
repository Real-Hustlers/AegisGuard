"""Persistent server-observed and collector-reported heartbeat health."""

import json
import math

from backend.storage.collector_identity import (
    CollectorIdentityError,
    normalize_certificate_fingerprint,
)


_ALLOWED_TRANSPORT_STATUS = {
    "HEALTHY",
    "BACKLOG",
    "RETRY_WAIT",
    "DEGRADED",
}


class CollectorHealthError(ValueError):
    """Raised when a collector health report cannot be persisted safely."""


def _optional_non_negative_int(value, field_name):
    if value is None:
        return None
    if isinstance(value, bool):
        raise CollectorHealthError(f"{field_name} must be an integer")
    try:
        normalized = int(value)
    except (TypeError, ValueError) as exc:
        raise CollectorHealthError(
            f"{field_name} must be an integer"
        ) from exc
    if normalized < 0:
        raise CollectorHealthError(
            f"{field_name} must be non-negative"
        )
    return normalized


def _optional_non_negative_float(value, field_name):
    if value is None:
        return None
    if isinstance(value, bool):
        raise CollectorHealthError(f"{field_name} must be numeric")
    try:
        normalized = float(value)
    except (TypeError, ValueError) as exc:
        raise CollectorHealthError(
            f"{field_name} must be numeric"
        ) from exc
    if not math.isfinite(normalized) or normalized < 0:
        raise CollectorHealthError(
            f"{field_name} must be a finite non-negative number"
        )
    return normalized


def _optional_bool(value, field_name):
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise CollectorHealthError(f"{field_name} must be a boolean")


def _optional_version(value):
    if value in (None, ""):
        return None
    normalized = str(value).strip()
    if not normalized:
        return None
    if len(normalized) > 128:
        raise CollectorHealthError(
            "collector version must be at most 128 characters"
        )
    return normalized


def normalize_reported_health(report):
    """Keep operational fields only; never trust client security assertions."""

    if report is None:
        report = {}
    if not isinstance(report, dict):
        raise CollectorHealthError("health must be a JSON object")

    status = report.get("status")
    if status in (None, ""):
        normalized_status = None
    else:
        normalized_status = str(status).strip().upper()
        if normalized_status not in _ALLOWED_TRANSPORT_STATUS:
            raise CollectorHealthError(
                "health.status must be HEALTHY, BACKLOG, "
                "RETRY_WAIT, or DEGRADED"
            )

    normalized = {
        "status": normalized_status,
        "pending_batches": _optional_non_negative_int(
            report.get("pending_batches"),
            "health.pending_batches",
        ),
        "checkpoint": _optional_non_negative_int(
            report.get("checkpoint"),
            "health.checkpoint",
        ),
        "collection_cursor": _optional_non_negative_int(
            report.get("collection_cursor"),
            "health.collection_cursor",
        ),
        "retry_in_seconds": _optional_non_negative_float(
            report.get("retry_in_seconds"),
            "health.retry_in_seconds",
        ),
        "last_successful_ack_at": _optional_non_negative_float(
            report.get("last_successful_ack_at"),
            "health.last_successful_ack_at",
        ),
        "certificate_rotation_pending": _optional_bool(
            report.get("certificate_rotation_pending"),
            "health.certificate_rotation_pending",
        ),
    }

    return {
        key: value
        for key, value in normalized.items()
        if value is not None
    }


def record_collector_heartbeat(
    conn,
    collector_id,
    *,
    peer_ip=None,
    mtls_required=False,
    mtls_verified=False,
    certificate_fingerprint=None,
    reported_version=None,
    reported_health=None,
):
    """Persist server trust observations separately from client health."""

    collector_id = str(collector_id or "").strip()
    if not collector_id:
        raise CollectorHealthError("collector_id is required")

    version = _optional_version(reported_version)
    health = normalize_reported_health(reported_health)

    certificate = None
    if certificate_fingerprint not in (None, ""):
        try:
            certificate = normalize_certificate_fingerprint(
                certificate_fingerprint
            )
        except CollectorIdentityError as exc:
            raise CollectorHealthError(
                "verified certificate fingerprint is invalid"
            ) from exc

    required = bool(mtls_required)
    verified = bool(mtls_verified)
    if verified and not certificate:
        raise CollectorHealthError(
            "mTLS verification requires a verified certificate fingerprint"
        )
    if required and not verified:
        raise CollectorHealthError(
            "required mTLS heartbeat was not verified"
        )

    cursor = conn.execute(
        """
        UPDATE collectors
        SET last_heartbeat_at = CURRENT_TIMESTAMP,
            heartbeat_peer_ip = ?,
            heartbeat_credential_authenticated = 1,
            heartbeat_mtls_required = ?,
            heartbeat_mtls_verified = ?,
            heartbeat_certificate_fingerprint = ?,
            reported_version = ?,
            reported_transport_status = ?,
            reported_pending_batches = ?,
            reported_checkpoint = ?,
            reported_collection_cursor = ?,
            reported_retry_in_seconds = ?,
            reported_last_successful_ack_at = ?,
            reported_certificate_rotation_pending = ?,
            reported_health_json = ?
        WHERE collector_id = ?
        """,
        (
            str(peer_ip or "").strip() or None,
            1 if required else 0,
            1 if verified else 0,
            certificate,
            version,
            health.get("status"),
            health.get("pending_batches"),
            health.get("checkpoint"),
            health.get("collection_cursor"),
            health.get("retry_in_seconds"),
            health.get("last_successful_ack_at"),
            (
                None
                if "certificate_rotation_pending" not in health
                else (
                    1
                    if health["certificate_rotation_pending"]
                    else 0
                )
            ),
            json.dumps(
                health,
                sort_keys=True,
                separators=(",", ":"),
            ),
            collector_id,
        ),
    )
    if cursor.rowcount != 1:
        conn.rollback()
        raise CollectorHealthError("unknown collector")

    conn.commit()
    return get_collector_health(conn, collector_id)


def get_collector_health(conn, collector_id):
    collector_id = str(collector_id or "").strip()
    if not collector_id:
        raise CollectorHealthError("collector_id is required")

    row = conn.execute(
        """
        SELECT collector_id,
               last_heartbeat_at,
               heartbeat_peer_ip,
               heartbeat_credential_authenticated,
               heartbeat_mtls_required,
               heartbeat_mtls_verified,
               heartbeat_certificate_fingerprint,
               reported_version,
               reported_transport_status,
               reported_pending_batches,
               reported_checkpoint,
               reported_collection_cursor,
               reported_retry_in_seconds,
               reported_last_successful_ack_at,
               reported_certificate_rotation_pending,
               reported_health_json
        FROM collectors
        WHERE collector_id = ?
        """,
        (collector_id,),
    ).fetchone()
    if row is None:
        raise CollectorHealthError("unknown collector")

    try:
        raw_report = json.loads(row[15] or "{}")
    except (TypeError, ValueError):
        raw_report = {}

    return {
        "collector_id": str(row[0]),
        "server_observed": {
            "last_heartbeat_at": row[1],
            "peer_ip": row[2],
            "credential_authenticated": bool(row[3]),
            "mtls_required": bool(row[4]),
            "mtls_verified": bool(row[5]),
            "certificate_fingerprint": row[6],
        },
        "collector_reported": {
            "version": row[7],
            "transport_status": row[8],
            "pending_batches": row[9],
            "checkpoint": row[10],
            "collection_cursor": row[11],
            "retry_in_seconds": row[12],
            "last_successful_ack_at": row[13],
            "certificate_rotation_pending": (
                None if row[14] is None else bool(row[14])
            ),
            "health": raw_report,
        },
    }
