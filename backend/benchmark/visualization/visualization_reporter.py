"""Visualization report generator."""

from __future__ import annotations

import json
from pathlib import Path


def generate_visualization_report(
    payload: dict,
    output_file="visualization_report.json",
):
    """
    Write dashboard visualization payload.
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