"""Benchmark result aggregation layer."""

from __future__ import annotations

from datetime import datetime, timezone


def aggregate_benchmark_results(
    generator=None,
    pipeline=None,
    storage=None,
    distributed=None,
) -> dict:
    """
    Combine all scalability benchmark outputs
    into a unified visualization payload.
    """

    components = {}

    if generator:
        components["generator"] = {
            "events": generator.get("total_events", 0),
            "events_per_second": generator.get(
                "events_per_second",
                0,
            ),
        }

    if pipeline:
        components["pipeline"] = {
            "events": pipeline.get(
                "total_events",
                0,
            ),
            "collector_eps": pipeline.get(
                "collector",
                {},
            ).get(
                "events_per_second",
                0,
            ),
            "analyzer_eps": pipeline.get(
                "analyzer",
                {},
            ).get(
                "events_per_second",
                0,
            ),
        }

    if storage:
        components["storage"] = {
            "events": storage.get(
                "events",
                0,
            ),
            "write_eps": storage.get(
                "write",
                {},
            ).get(
                "events_per_second",
                0,
            ),
        }

    if distributed:
        components["distributed"] = {
            "nodes": distributed.get(
                "nodes",
                0,
            ),
            "events": distributed.get(
                "total_events",
                0,
            ),
            "events_per_second": distributed.get(
                "events_per_second",
                0,
            ),
        }

    return {
        "benchmark": (
            "AegisGuard Scalability Visualization"
        ),
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "components": components,
    }