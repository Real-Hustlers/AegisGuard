"""Pipeline latency measurements."""

from __future__ import annotations

import time


def measure_pipeline_latency(events):
    start = time.perf_counter()

    analyzed = 0
    detections = 0

    for event in events:

        if event.get("action") == "login_failed":
            detections += 1

        analyzed += 1

    elapsed = (
        time.perf_counter() - start
    )

    return {
        "total_events": analyzed,
        "detections": detections,
        "pipeline_latency_seconds": elapsed,
        "pipeline_latency_ms": (
            elapsed * 1000
        ),
        "events_per_second": (
            analyzed / elapsed
            if elapsed > 0
            else 0
        ),
    }