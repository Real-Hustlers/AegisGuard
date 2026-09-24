"""Pipeline benchmark runner."""

from backend.benchmark.generator import (
    generate_security_events,
)

from .collector_benchmark import (
    benchmark_collector,
)

from .analyzer_benchmark import (
    benchmark_analyzer,
)

from .latency import (
    measure_pipeline_latency,
)


def run_pipeline_benchmark(
    event_count: int,
):

    events = list(
        generate_security_events(
            event_count
        )
    )

    collector_result = benchmark_collector(
        events
    )

    analyzer_result = benchmark_analyzer(
        events
    )

    latency_result = measure_pipeline_latency(
        events
    )

    return {
        "collector": collector_result,
        "analyzer": analyzer_result,
        "pipeline_latency": latency_result,
    }