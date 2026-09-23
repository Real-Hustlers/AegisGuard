"""Governed optional local raw-output handling for the legacy collector."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping, Optional


class RawOutputPolicyError(ValueError):
    """Raised when an unsafe local raw-output path is requested."""


def raw_output_enabled(config: Mapping[str, Any]) -> bool:
    """Require an explicit boolean opt-in for local raw-log persistence."""
    return config.get("raw_output_enabled") is True


def resolve_raw_output_path(
    filename: str,
    *,
    base_dir: Optional[Path] = None,
) -> Path:
    """Resolve one relative output path beneath the selected runtime root."""

    value = str(filename or "").strip()
    if not value:
        raise RawOutputPolicyError("raw output filename is required")

    relative = Path(value)
    if relative.is_absolute():
        raise RawOutputPolicyError(
            "raw output path must be relative to the runtime directory"
        )

    root = (Path.cwd() if base_dir is None else Path(base_dir)).resolve()
    target = (root / relative).resolve()

    if target == root or root not in target.parents:
        raise RawOutputPolicyError(
            "raw output path must remain inside the runtime directory"
        )

    return target


def persist_raw_logs(
    logs,
    filename: str,
    *,
    base_dir: Optional[Path] = None,
) -> Path:
    """Atomically persist an explicitly approved local raw-log copy.

    Owner-only POSIX mode is requested where supported. This is defense in
    depth and is not encryption at rest.
    """

    target = resolve_raw_output_path(filename, base_dir=base_dir)
    target.parent.mkdir(parents=True, exist_ok=True)

    temp_path = target.with_name(target.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(temp_path, flags, 0o600)

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(logs, file, indent=4, default=str)
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_path, target)

        try:
            os.chmod(target, 0o600)
        except OSError:
            pass

    except Exception:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    return target
