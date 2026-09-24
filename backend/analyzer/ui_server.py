"""Loopback-only packaged server for the AegisGuard human UI."""

from __future__ import annotations

import os
from typing import Mapping

from werkzeug.serving import make_server


UI_BIND_HOST_ENV = "AEGISGUARD_UI_BIND_HOST"
UI_PORT_ENV = "AEGISGUARD_UI_PORT"

_ALLOWED_LOOPBACK_HOSTS = {
    "127.0.0.1",
    "localhost",
    "::1",
}


def load_ui_server_config(
    env: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Load the packaged human-UI listener configuration.

    The direct packaged UI is intentionally loopback-only.
    Remote exposure requires a separately governed deployment boundary.
    """

    values = (
        os.environ
        if env is None
        else env
    )

    host = str(
        values.get(
            UI_BIND_HOST_ENV,
            "127.0.0.1",
        )
        or ""
    ).strip()

    if host not in _ALLOWED_LOOPBACK_HOSTS:
        raise ValueError(
            "AEGISGUARD_UI_BIND_HOST must be a loopback host"
        )

    try:
        port = int(
            values.get(
                UI_PORT_ENV,
                "5000",
            )
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "AEGISGUARD_UI_PORT must be an integer"
        ) from exc

    if not 1 <= port <= 65535:
        raise ValueError(
            "AEGISGUARD_UI_PORT must be between 1 and 65535"
        )

    return {
        "host": host,
        "port": port,
    }


def main():
    config = load_ui_server_config()

    from backend.analyzer.app import (
        app,
        debug_print,
    )

    server = make_server(
        str(config["host"]),
        int(config["port"]),
        app,
        threaded=True,
    )

    debug_print(
        "[UI SERVER] "
        f"http://{config['host']}:{config['port']} "
        "loopback_only=True "
        "debug=False"
    )

    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
