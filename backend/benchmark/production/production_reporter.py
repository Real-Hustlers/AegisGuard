"""Production validation report generator."""

from __future__ import annotations

import json
from pathlib import Path


def generate_production_report(
    result: dict,
    output_file="production_validation_report.json",
):
    """
    Save final production validation evidence.
    """

    path = Path(output_file)

    path.write_text(
        json.dumps(
            result,
            indent=2,
        ),
        encoding="utf-8",
    )

    return path