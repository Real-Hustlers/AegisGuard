"""Production scalability validation runner."""

from __future__ import annotations

import time

from ..runner import run_generator_benchmark
from ..pipeline.pipeline_runner import run_pipeline_benchmark
from ..storage.storage_runner import run_storage_benchmark
from ..distributed.distributed_runner import run_distributed_benchmark


def run_production_validation(
    events: int,
    nodes: int,
) -> dict:
    """
    Execute complete scalability validation.

    Combines:
    - generator benchmark
    - pipeline benchmark
    - storage benchmark
    - distributed benchmark
    """

    start = time.perf_counter()

    generator = run_generator_benchmark(
        events
    )

    pipeline = run_pipeline_benchmark(
        events
    )

    storage = run_storage_benchmark(
        events
    )

    distributed = run_distributed_benchmark(
        nodes=nodes,
        events_per_node=events // nodes,
    )

    elapsed = (
        time.perf_counter()
        - start
    )

    return {
        "benchmark":
            "AegisGuard Production Scale Validation",

        "input_events":
            events,

        "nodes":
            nodes,

        "total_validation_seconds":
            elapsed,

        "generator":
            generator.to_dict(),

        "pipeline":
            pipeline,

        "storage":
            storage,

        "distributed":
            distributed,

        "status":
            "validated",
    }