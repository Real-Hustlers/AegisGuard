"""Durable server-side collector batch persistence."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from backend.platform.data_privacy import redact_sensitive_text


DEFAULT_FAILED_PAYLOAD_RETENTION_DAYS = 30
MAX_FAILED_PAYLOAD_RETENTION_DAYS = 365


def _failed_payload_cutoff(
    *,
    retention_days: int,
    now: Optional[datetime] = None,
) -> str:
    days = int(retention_days)
    if days <= 0 or days > MAX_FAILED_PAYLOAD_RETENTION_DAYS:
        raise ValueError(
            "failed payload retention days must be between 1 and "
            f"{MAX_FAILED_PAYLOAD_RETENTION_DAYS}"
        )

    current = datetime.now(timezone.utc) if now is None else now
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)

    return (
        current - timedelta(days=days)
    ).strftime("%Y-%m-%d %H:%M:%S")


def scrub_expired_failed_payloads(
    conn: sqlite3.Connection,
    *,
    retention_days: int = DEFAULT_FAILED_PAYLOAD_RETENTION_DAYS,
    now: Optional[datetime] = None,
) -> int:
    """Scrub expired raw payload copies from FAILED ingest rows."""

    cutoff = _failed_payload_cutoff(
        retention_days=retention_days,
        now=now,
    )
    cursor = conn.execute(
        """
        UPDATE collector_ingest_batches
        SET payload_json = '{}'
        WHERE state = 'FAILED'
          AND received_at < ?
          AND payload_json != '{}'
        """,
        (cutoff,),
    )
    conn.commit()
    return int(cursor.rowcount)


def persist_collector_batch(
    conn: sqlite3.Connection,
    payload: Dict[str, Any],
    peer_ip: str = None,
) -> Tuple[bool, str]:
    """Persist a collector batch before acknowledgement.

    Returns (inserted, state). Retries with the same batch_id are idempotent.
    """

    batch_id = str(payload.get("batch_id") or "").strip()
    collector_id = str(payload.get("collector_id") or "").strip()
    hostname = str(payload.get("hostname") or "").strip()
    logs = payload.get("logs")

    if not batch_id:
        raise ValueError("batch_id is required")
    if not collector_id:
        raise ValueError("collector_id is required")
    if not hostname:
        raise ValueError("hostname is required")
    if not isinstance(logs, list):
        raise ValueError("logs must be a list")

    record_ids = []
    for log in logs:
        if not isinstance(log, dict):
            continue
        value = log.get("record_id", log.get("RecordId"))
        try:
            if value not in (None, ""):
                record_ids.append(int(value))
        except (TypeError, ValueError):
            continue

    max_record_id = max(record_ids) if record_ids else None
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)

    cursor = conn.execute(
        """
        INSERT OR IGNORE INTO collector_ingest_batches(
            batch_id, collector_id, hostname, peer_ip, payload_json,
            event_count, max_record_id, state
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'QUEUED')
        """,
        (
            batch_id,
            collector_id,
            hostname,
            peer_ip,
            payload_json,
            len(logs),
            max_record_id,
        ),
    )
    inserted = bool(cursor.rowcount)
    conn.commit()

    row = conn.execute(
        "SELECT state FROM collector_ingest_batches WHERE batch_id = ?",
        (batch_id,),
    ).fetchone()
    state = str(row[0]) if row else "QUEUED"
    return inserted, state


def claim_next_collector_batch(
    conn: sqlite3.Connection,
) -> Optional[Dict[str, Any]]:
    """Atomically claim the oldest queued collector batch.

    ``BEGIN IMMEDIATE`` serializes queue claims so two workers cannot claim
    the same row. ``attempts`` increments only when a claim succeeds.
    """

    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT batch_id, collector_id, hostname, peer_ip, payload_json,
                   event_count, max_record_id, attempts
            FROM collector_ingest_batches
            WHERE state = 'QUEUED'
            ORDER BY received_at, batch_id
            LIMIT 1
            """
        ).fetchone()

        if row is None:
            conn.commit()
            return None

        batch_id = str(row[0])
        cursor = conn.execute(
            """
            UPDATE collector_ingest_batches
            SET state = 'PROCESSING',
                attempts = attempts + 1,
                last_error = NULL
            WHERE batch_id = ? AND state = 'QUEUED'
            """,
            (batch_id,),
        )

        if cursor.rowcount != 1:
            conn.rollback()
            return None

        conn.commit()
        return {
            "batch_id": batch_id,
            "collector_id": str(row[1]),
            "hostname": str(row[2]),
            "peer_ip": row[3],
            "payload": json.loads(str(row[4])),
            "event_count": int(row[5]),
            "max_record_id": row[6],
            "attempts": int(row[7]) + 1,
        }
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise


def mark_collector_batch_processed(
    conn: sqlite3.Connection,
    batch_id: str,
) -> bool:
    """Mark one claimed batch as successfully processed."""

    cursor = conn.execute(
        """
        UPDATE collector_ingest_batches
        SET state = 'PROCESSED',
            processed_at = CURRENT_TIMESTAMP,
            payload_json = '{}',
            last_error = NULL
        WHERE batch_id = ? AND state = 'PROCESSING'
        """,
        (str(batch_id),),
    )
    conn.commit()
    return cursor.rowcount == 1


def mark_collector_batch_failed(
    conn: sqlite3.Connection,
    batch_id: str,
    error: str,
) -> bool:
    """Mark one claimed batch as failed while preserving its error."""

    safe_error = redact_sensitive_text(error)
    cursor = conn.execute(
        """
        UPDATE collector_ingest_batches
        SET state = 'FAILED',
            processed_at = NULL,
            last_error = ?
        WHERE batch_id = ? AND state = 'PROCESSING'
        """,
        (safe_error, str(batch_id)),
    )
    conn.commit()
    return cursor.rowcount == 1


def recover_processing_collector_batches(
    conn: sqlite3.Connection,
) -> int:
    """Requeue batches stranded in PROCESSING after analyzer interruption.

    The analyzer currently runs one durable ingest worker per process. On
    startup, any PROCESSING row is therefore work that was claimed by the
    previous analyzer process but never completed. Event insertion remains
    idempotent at the database layer, so replay after recovery is safe.
    """

    cursor = conn.execute(
        """
        UPDATE collector_ingest_batches
        SET state = 'QUEUED',
            processed_at = NULL,
            last_error = 'recovered after interrupted analyzer processing'
        WHERE state = 'PROCESSING'
        """
    )
    conn.commit()
    return int(cursor.rowcount)
