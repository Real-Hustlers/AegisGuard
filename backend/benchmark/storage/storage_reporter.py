"""Storage benchmark reporting."""

from __future__ import annotations

import json
from pathlib import Path


def generate_storage_report(
    results,
    output_file="storage_benchmark_report.json",
):

    report = {
        "benchmark": "AegisGuard Storage Benchmark",
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