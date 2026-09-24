"""Benchmark execution runner."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from .generator import generate_security_events
from .models import BenchmarkResult
from .metrics import ResourceMonitor


def run_generator_benchmark(
    event_count: int,
    benchmark_name: str = "synthetic-event-generation",
) -> BenchmarkResult:
    """
    Execute a synthetic event generation benchmark.
    """

    start_time = datetime.now(
        timezone.utc
    )

    monitor = ResourceMonitor()

    monitor.start()

    start = time.perf_counter()

    processed = 0

    for _event in generate_security_events(
        event_count
    ):
        processed += 1

    elapsed = (
        time.perf_counter()
        -
        start
    )

    monitor.stop()

    end_time = datetime.now(
        timezone.utc
    )

    eps = (
        processed / elapsed
        if elapsed > 0
        else 0
    )

    return BenchmarkResult(
        benchmark_name=benchmark_name,
        total_events=processed,
        start_time=start_time,
        end_time=end_time,
        processing_seconds=elapsed,
        events_per_second=eps,
        average_latency_ms=(
            elapsed / processed * 1000
            if processed
            else 0
        ),
        resources=monitor.result(),
    )
