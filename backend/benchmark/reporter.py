"""Benchmark reporting utilities."""

from __future__ import annotations

import json
from pathlib import Path


def generate_report(
    results,
    output_file="benchmark_report.json",
):
    report = {
        "benchmark": "AegisGuard Scalability Validation",
        "scenarios": [
            result.to_dict()
            for result in results
        ],
    }

    path = Path(output_file)

    path.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    return path


def generate_markdown_report(
    results,
    output_file="benchmark_report.md",
):
    lines = [
        "# AegisGuard Scalability Validation",
        "",
        "| Scenario | Events | EPS | Latency (ms) | CPU % | Memory MB |",
        "|---|---:|---:|---:|---:|---:|",
    ]

    for result in results:
        data = result.to_dict()

        resources = data["resources"]

        lines.append(
            "| {name} | {events:,} | {eps:,.2f} | {latency:.6f} | {cpu:.2f} | {memory:.2f} |".format(
                name=data["benchmark_name"],
                events=data["total_events"],
                eps=data["events_per_second"],
                latency=data["average_latency_ms"],
                cpu=resources["cpu_percent"],
                memory=resources["memory_mb"],
            )
        )

    Path(output_file).write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    return Path(output_file)
