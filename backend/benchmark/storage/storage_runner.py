"""Storage benchmark runner."""

from __future__ import annotations

from .database_writer import benchmark_write
from .query_benchmark import benchmark_query


def generate_events(count: int) -> list[dict]:
    return [
        {
            "event_id": i,
            "type": "security_event",
            "severity": "medium",
            "source": "benchmark",
        }
        for i in range(count)
    ]


def run_storage_benchmark(count: int) -> dict:

    events = generate_events(count)

    write_result = benchmark_write(events)

    query_result = benchmark_query(events)

    return {
        "events": count,
        "write": write_result,
        "query": query_result,
    }