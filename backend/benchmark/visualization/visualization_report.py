"""Complete visualization report builder."""

from __future__ import annotations

from pathlib import Path
import json


def generate_visualization_report(
    payload: dict,
    output_file="aegisguard_scalability_dashboard.json",
):
    """
    Generate final dashboard JSON report.
    """

    path = Path(output_file)

    path.write_text(
        json.dumps(
            payload,
            indent=2,
        ),
        encoding="utf-8",
    )

    return path