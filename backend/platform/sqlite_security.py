"""SQLite data-at-rest hardening primitives for AegisGuard Enterprise."""

from __future__ import annotations

import sqlite3
from typing import Any


class SQLiteSecurityError(RuntimeError):
    """Raised when required SQLite security settings cannot be enabled."""


def configure_sqlite_data_security(conn: sqlite3.Connection) -> dict[str, Any]:
    """Enable conservative SQLite security settings on one connection."""

    conn.execute("PRAGMA secure_delete = ON")
    conn.execute("PRAGMA temp_store = MEMORY")

    secure_delete_row = conn.execute("PRAGMA secure_delete").fetchone()
    temp_store_row = conn.execute("PRAGMA temp_store").fetchone()

    secure_delete = int(secure_delete_row[0]) if secure_delete_row else 0
    temp_store = int(temp_store_row[0]) if temp_store_row else 0

    if secure_delete != 1:
        raise SQLiteSecurityError("SQLite secure_delete could not be enabled")
    if temp_store != 2:
        raise SQLiteSecurityError("SQLite temp_store=MEMORY could not be enabled")

    return {
        "secure_delete": True,
        "temp_store_memory": True,
    }
