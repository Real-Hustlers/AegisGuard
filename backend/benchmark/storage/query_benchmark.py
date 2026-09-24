"""Storage query benchmark."""

from __future__ import annotations

import time


def benchmark_query(events: list[dict], limit: int = 100) -> dict:

    start = time.perf_counter()

    results = events[:limit]

    elapsed = time.perf_counter() - start

    return {
        "component": "storage_query",
        "operation": "query",
        "returned_records": len(results),
        "query_latency_ms": elapsed * 1000,
    }