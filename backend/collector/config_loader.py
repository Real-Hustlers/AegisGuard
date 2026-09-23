import json
from pathlib import Path

from backend.deployment.runtime_paths import (
    resolve_collector_config_path,
)


def get_config_path():
    """Return the supported Collector configuration location."""

    return resolve_collector_config_path(
        source_path=(
            Path(__file__)
            .resolve()
            .parent
            / "config.json"
        ),
    )


def load_config():
    config_path = get_config_path()

    print(
        f"Loading config from: {config_path}",
        flush=True,
    )

    if not config_path.exists():
        raise FileNotFoundError(
            f"config.json not found: {config_path}"
        )

    with open(
        config_path,
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)
