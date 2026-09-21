"""Durable local collector spool and checkpoint storage."""

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional


class CollectorState:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
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
                    last_error TEXT
                );
                """
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

    def get_checkpoint(self) -> Optional[int]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key='last_acked_record_id'"
            ).fetchone()
            return int(row["value"]) if row else None
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
                SELECT batch_id, payload_json, max_record_id, attempts, last_error
                FROM outbound_batches
                ORDER BY created_at, batch_id
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
                }
                for row in rows
            ]
        finally:
            conn.close()

    def mark_attempt(self, batch_id: str, error: Optional[str] = None) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                UPDATE outbound_batches
                SET attempts = attempts + 1, last_error = ?
                WHERE batch_id = ?
                """,
                (error, batch_id),
            )
            conn.commit()
        finally:
            conn.close()

    def acknowledge(self, batch_id: str) -> None:
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
                "DELETE FROM outbound_batches WHERE batch_id = ?",
                (batch_id,),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
