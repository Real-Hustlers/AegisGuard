import json
import sys
from pathlib import Path


def load_config():

    if getattr(sys, "frozen", False):
        # Look for config.json next to the EXE
        config_path = (
            Path(sys.executable).resolve().parent
            / "config.json"
        )
    else:
        # Normal Python development
        config_path = (
            Path(__file__).resolve().parent
            / "config.json"
        )

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