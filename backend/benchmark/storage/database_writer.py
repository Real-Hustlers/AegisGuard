"""Storage write benchmark."""

from __future__ import annotations

import time
from datetime import datetime, timezone


def benchmark_write(events: list[dict]) -> dict:
    start_time = datetime.now(timezone.utc)

    start = time.perf_counter()

    storage = []

    for event in events:
        storage.append(event)

    elapsed = time.perf_counter() - start

    end_time = datetime.now(timezone.utc)

    total = len(events)

    return {
        "component": "storage_writer",
        "operation": "write",
        "total_events": total,
        "processing_seconds": elapsed,
        "events_per_second": (
            total / elapsed if elapsed else 0
        ),
        "storage_size": len(storage),
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
    }