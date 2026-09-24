"""Pipeline benchmark reporting."""

from __future__ import annotations

import json
from pathlib import Path


def generate_pipeline_report(
    results,
    output_file="pipeline_benchmark_report.json",
):

    report = {
        "benchmark":
            "AegisGuard Pipeline Throughput Validation",

        "scenarios": results,
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