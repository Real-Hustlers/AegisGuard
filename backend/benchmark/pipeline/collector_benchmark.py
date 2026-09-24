"""Collector throughput benchmark."""

from __future__ import annotations

import time
from datetime import datetime, timezone


def benchmark_collector(
    events,
):
    """
    Measure collector ingestion throughput.

    Simulates receiving security events
    from endpoint/network sources.
    """

    start_time = datetime.now(
        timezone.utc
    )

    start = time.perf_counter()

    received = 0

    queue = []

    for event in events:
        queue.append(event)
        received += 1

    elapsed = (
        time.perf_counter()
        - start
    )

    end_time = datetime.now(
        timezone.utc
    )

    return {
        "component": "collector",
        "total_events": received,
        "processing_seconds": elapsed,
        "events_per_second": (
            received / elapsed
            if elapsed > 0
            else 0
        ),
        "average_latency_ms": (
            elapsed / received * 1000
            if received
            else 0
        ),
        "queue_size": len(queue),
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
    }