"""Concurrent distributed-load benchmark runner."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from .load_generator import generate_events
from .node_simulator import simulate_node


def _run_node(
    node_index: int,
    events_per_node: int,
) -> dict:
    node_name = (
        f"collector-node-{node_index + 1}"
    )

    events = generate_events(
        node_name,
        events_per_node,
    )

    return simulate_node(
        node_name,
        events,
    )


def run_distributed_benchmark(
    nodes: int = 4,
    events_per_node: int = 100_000,
) -> dict:
    """
    Run concurrent collector-node simulation.

    Aggregate throughput is calculated from
    total events divided by real suite wall time.
    """

    if nodes <= 0:
        raise ValueError(
            "nodes must be greater than zero"
        )

    if events_per_node < 0:
        raise ValueError(
            "events_per_node cannot be negative"
        )

    wall_start = time.perf_counter()

    with ThreadPoolExecutor(
        max_workers=nodes
    ) as executor:
        futures = [
            executor.submit(
                _run_node,
                index,
                events_per_node,
            )
            for index in range(nodes)
        ]

        node_results = [
            future.result()
            for future in futures
        ]

    wall_elapsed = (
        time.perf_counter()
        - wall_start
    )

    total_events = sum(
        result["events"]
        for result in node_results
    )

    return {
        "benchmark":
            "distributed-load-validation",
        "concurrency_model":
            "threaded-node-simulation",
        "nodes": nodes,
        "events_per_node": events_per_node,
        "total_events": total_events,
        "processing_seconds": wall_elapsed,
        "events_per_second": (
            total_events / wall_elapsed
            if wall_elapsed
            else 0
        ),
        "nodes_result": node_results,
    }
