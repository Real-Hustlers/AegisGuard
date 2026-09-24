"""Benchmark suite execution."""

from __future__ import annotations

from .runner import run_generator_benchmark
from .scenarios import DEFAULT_SCENARIOS
from .reporter import (
    generate_report,
    generate_markdown_report,
)


def run_benchmark_suite(
    output_file="benchmark_report.json",
):

    results = []

    for scenario in DEFAULT_SCENARIOS:

        print(
            f"Running {scenario.name}: "
            f"{scenario.event_count} events"
        )

        result = run_generator_benchmark(
            scenario.event_count,
            benchmark_name=scenario.name,
        )

        results.append(result)

        print(result.to_dict())

    json_report = generate_report(
        results,
        output_file,
    )

    markdown_report = generate_markdown_report(
        results,
    )

    print(
        f"JSON Report: {json_report}"
    )

    print(
        f"Markdown Report: {markdown_report}"
    )

    return results
