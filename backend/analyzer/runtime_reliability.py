"""Analyzer runtime reliability probes and startup preflight."""

from __future__ import annotations

import tempfile
from pathlib import Path


CORE_TABLES = frozenset({
    "security_logs",
    "incidents",
    "settings",
})


class RuntimeReadinessError(RuntimeError):
    """Raised when the Analyzer cannot safely enter service."""


def _database_ready(connection_factory):
    conn = None
    try:
        conn = connection_factory()

        quick_check = conn.execute(
            "PRAGMA quick_check(1)"
        ).fetchone()
        if (
            quick_check is None
            or str(quick_check[0]).strip().lower() != "ok"
        ):
            return False

        rows = conn.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type='table'
        """).fetchall()
        names = {
            str(row[0])
            for row in rows
        }
        return CORE_TABLES.issubset(names)
    except Exception:
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _data_directory_ready(data_directory):
    try:
        path = Path(data_directory)
        path.mkdir(
            parents=True,
            exist_ok=True,
        )
        if not path.is_dir():
            return False

        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=".aegisguard-readiness-",
            dir=str(path),
            delete=True,
        ) as handle:
            handle.write(b"ready")
            handle.flush()

        return True
    except Exception:
        return False


def analyzer_liveness():
    """Return a deliberately minimal process-liveness response."""
    return {
        "service": "aegisguard-analyzer",
        "status": "ok",
    }


def probe_analyzer_readiness(
    connection_factory,
    data_directory,
):
    """Return non-sensitive dependency readiness for the Analyzer."""
    database_ok = _database_ready(
        connection_factory
    )
    data_directory_ok = _data_directory_ready(
        data_directory
    )

    ready = (
        database_ok
        and data_directory_ok
    )

    return {
        "service": "aegisguard-analyzer",
        "status": (
            "ready"
            if ready
            else "not_ready"
        ),
        "checks": {
            "database": {
                "ok": database_ok,
                "reason": (
                    None
                    if database_ok
                    else "database_unavailable"
                ),
            },
            "data_directory": {
                "ok": data_directory_ok,
                "reason": (
                    None
                    if data_directory_ok
                    else "data_directory_unavailable"
                ),
            },
        },
    }


def validate_analyzer_startup(
    connection_factory,
    data_directory,
):
    """Fail closed before network service when core dependencies are not ready."""
    report = probe_analyzer_readiness(
        connection_factory,
        data_directory,
    )
    if report["status"] == "ready":
        return report

    failed = [
        name
        for name, result in report["checks"].items()
        if not result["ok"]
    ]
    raise RuntimeReadinessError(
        "Analyzer startup preflight failed: "
        + ", ".join(failed)
    )
