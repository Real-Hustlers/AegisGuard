import json
import sys
from pathlib import Path


def get_config_path():
    """Return the one supported Collector configuration location."""

    if getattr(sys, "frozen", False):
        # Look for config.json next to the EXE
        return (
            Path(sys.executable).resolve().parent
            / "config.json"
        )
    else:
        # Normal Python development
        return (
            Path(__file__).resolve().parent
            / "config.json"
        )


def load_config():

    config_path = get_config_path()

    print(
        f"Loading config from: {config_path}",
        flush=True
    )

    if not config_path.exists():
        raise FileNotFoundError(
            f"config.json not found: {config_path}"
        )

    with open(
        config_path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)
