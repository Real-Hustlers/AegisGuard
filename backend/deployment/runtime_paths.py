"""Writable runtime-path resolution for packaged AegisGuard services."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Mapping


ANALYZER_DATA_DIR_ENV = "AEGISGUARD_DATA_DIR"


def resolve_analyzer_data_dir(
    *,
    environ: Mapping[str, str] | None = None,
    frozen: bool | None = None,
    source_root: str | Path | None = None,
) -> Path:
    """Resolve the Analyzer's writable runtime directory.

    Explicit configuration wins.

    Source mode preserves the repository-root behavior used by
    development and tests.

    Frozen Windows deployments default to ProgramData and never fall
    back to writing beside the executable in Program Files.
    """

    values = (
        os.environ
        if environ is None
        else environ
    )

    configured = str(
        values.get(
            ANALYZER_DATA_DIR_ENV,
            "",
        )
        or ""
    ).strip()

    if configured:
        return Path(
            os.path.expandvars(
                os.path.expanduser(
                    configured
                )
            )
        ).resolve()

    if frozen is None:
        frozen = bool(
            getattr(
                sys,
                "frozen",
                False,
            )
        )

    if frozen:
        program_data = str(
            values.get(
                "ProgramData",
                values.get(
                    "PROGRAMDATA",
                    "",
                ),
            )
            or ""
        ).strip()

        if not program_data:
            raise RuntimeError(
                "ProgramData is required for "
                "frozen Analyzer deployment "
                "when AEGISGUARD_DATA_DIR "
                "is not configured"
            )

        return (
            Path(program_data)
            / "AegisGuard"
            / "Analyzer"
        ).resolve()

    if source_root is not None:
        return Path(
            source_root
        ).resolve()

    return (
        Path(__file__)
        .resolve()
        .parents[2]
    )
