"""Distributed node simulator."""

from __future__ import annotations

import time


def simulate_node(
    node_name: str,
    events,
):
    start = time.perf_counter()

    processed = 0

    for _event in events:
        processed += 1

    elapsed = time.perf_counter() - start

    return {
        "node": node_name,
        "events": processed,
        "processing_seconds": elapsed,
        "events_per_second": (
            processed / elapsed
            if elapsed
            else 0
        ),
    }