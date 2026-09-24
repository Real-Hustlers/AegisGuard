"""Production suite report generator."""

from __future__ import annotations

import json
from pathlib import Path


def generate_production_suite_report(
    results,
    output_file="production_scale_validation_report.json",
):
    report = {
        "benchmark":
            "AegisGuard Production Scale Validation",

        "scenarios":
            results,
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