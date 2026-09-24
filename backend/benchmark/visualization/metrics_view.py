"""Benchmark KPI visualization helpers."""

from __future__ import annotations


def create_metrics_view(
    aggregated: dict,
) -> dict:
    """
    Generate simplified KPI metrics
    for dashboards and reports.
    """

    components = aggregated.get(
        "components",
        {},
    )

    metrics = {}

    for name, data in components.items():

        metrics[name] = {
            "event_volume":
                data.get(
                    "events",
                    0,
                ),

            "throughput_eps":
                data.get(
                    "events_per_second",
                    data.get(
                        "analyzer_eps",
                        data.get(
                            "write_eps",
                            0,
                        ),
                    ),
                ),
        }

    return {
        "dashboard_metrics": metrics,
        "component_count": len(metrics),
    }