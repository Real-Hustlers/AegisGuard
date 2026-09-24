"""Visualization benchmark runner."""

from __future__ import annotations

from .aggregator import aggregate_benchmark_results
from .dashboard_data import build_dashboard_payload
from .metrics_view import create_metrics_view


def run_visualization_pipeline(
    generator=None,
    pipeline=None,
    storage=None,
    distributed=None,
):
    """
    Build complete visualization payload.
    """

    aggregated = aggregate_benchmark_results(
        generator=generator,
        pipeline=pipeline,
        storage=storage,
        distributed=distributed,
    )

    dashboard = build_dashboard_payload(
        aggregated
    )

    metrics = create_metrics_view(
        aggregated
    )

    return {
        "aggregation": aggregated,
        "dashboard": dashboard,
        "metrics": metrics,
    }