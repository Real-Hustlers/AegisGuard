import json
import sys
from pathlib import Path


def load_config():

    if getattr(sys, "frozen", False):
        # Running as PyInstaller EXE
        base_dir = Path(sys._MEIPASS)
    else:
        # Running normally from Python
        base_dir = Path(__file__).resolve().parent

    config_path = base_dir / "config.json"

    print(f"Loading config from: {config_path}", flush=True)

    if not config_path.exists():
        raise FileNotFoundError(
            f"config.json not found at: {config_path}"
        )

    with open(config_path, "r", encoding="utf-8") as file:
        config = json.load(file)

    return config