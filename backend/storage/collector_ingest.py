"""Durable server-side collector batch persistence."""

import json
import sqlite3
from typing import Any, Dict, Tuple


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
