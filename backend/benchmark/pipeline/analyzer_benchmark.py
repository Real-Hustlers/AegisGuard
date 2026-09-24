"""Analyzer throughput benchmark."""

from __future__ import annotations

import time
from datetime import datetime, timezone


def benchmark_analyzer(events):
    """
    Measure analyzer processing throughput.

    Simulates security event analysis stage.
    """

    start_time = datetime.now(
        timezone.utc
    )

    start = time.perf_counter()

    analyzed = 0
    detections = 0

    for event in events:

        # Simulated analyzer checks
        if event.get("action") == "login_failed":
            detections += 1

        analyzed += 1

    elapsed = (
        time.perf_counter()
        - start
    )

    end_time = datetime.now(
        timezone.utc
    )

    return {
        "component": "analyzer",
        "total_events": analyzed,
        "detections": detections,
        "processing_seconds": elapsed,
        "events_per_second": (
            analyzed / elapsed
            if elapsed > 0
            else 0
        ),
        "average_latency_ms": (
            elapsed / analyzed * 1000
            if analyzed
            else 0
        ),
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
    }