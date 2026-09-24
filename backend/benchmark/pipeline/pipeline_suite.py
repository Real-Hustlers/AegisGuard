"""Pipeline benchmark suite."""

from __future__ import annotations

from .pipeline_runner import (
    run_pipeline_benchmark,
)


PIPELINE_SCENARIOS = [
    10_000,
    100_000,
    1_000_000,
    10_000_000,
]


def run_pipeline_suite():

    results = []

    for count in PIPELINE_SCENARIOS:

        print(
            f"Running pipeline benchmark: {count} events"
        )

        result = run_pipeline_benchmark(
            count
        )

        results.append(
            {
                "events": count,
                "result": result,
            }
        )

    return results