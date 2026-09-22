"""Fail-closed mTLS listener for remote AegisGuard collectors."""

import hashlib
import os
import ssl
from pathlib import Path

from werkzeug.serving import WSGIRequestHandler, make_server


def _require_file(value, field_name):
    raw = str(value or "").strip()
    if not raw:
        raise ValueError(f"{field_name} is required")
    path = Path(raw).expanduser()
    if not path.is_file():
        raise ValueError(f"{field_name} does not exist: {path}")
    return str(path.resolve())


def load_mtls_server_config(env=None):
    values = os.environ if env is None else env

    host = str(
        values.get("AEGISGUARD_TLS_BIND_HOST") or "0.0.0.0"
    ).strip()
    if not host:
        raise ValueError("AEGISGUARD_TLS_BIND_HOST must not be empty")

    try:
        port = int(values.get("AEGISGUARD_TLS_PORT") or "5443")
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "AEGISGUARD_TLS_PORT must be an integer"
        ) from exc

    if not 1 <= port <= 65535:
        raise ValueError(
            "AEGISGUARD_TLS_PORT must be between 1 and 65535"
        )

    return {
        "host": host,
        "port": port,
        "server_certificate": _require_file(
            values.get("AEGISGUARD_TLS_CERT_FILE"),
            "AEGISGUARD_TLS_CERT_FILE",
        ),
        "server_private_key": _require_file(
            values.get("AEGISGUARD_TLS_KEY_FILE"),
            "AEGISGUARD_TLS_KEY_FILE",
        ),
        "client_ca": _require_file(
            values.get("AEGISGUARD_TLS_CLIENT_CA_FILE"),
            "AEGISGUARD_TLS_CLIENT_CA_FILE",
        ),
    }


def build_mtls_ssl_context(
    server_certificate,
    server_private_key,
    client_ca,
):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(
        certfile=str(server_certificate),
        keyfile=str(server_private_key),
    )
    context.load_verify_locations(cafile=str(client_ca))
    return context


def inject_verified_client_certificate(environ, connection):
    environ["SSL_CLIENT_VERIFY"] = "FAILED"
    environ.pop("SSL_CLIENT_FINGERPRINT", None)

    if connection is None:
        return environ

    try:
        certificate_der = connection.getpeercert(binary_form=True)
    except (AttributeError, OSError, ssl.SSLError):
        return environ

    if not certificate_der:
        return environ

    environ["SSL_CLIENT_VERIFY"] = "SUCCESS"
    environ["SSL_CLIENT_FINGERPRINT"] = hashlib.sha256(
        certificate_der
    ).hexdigest()
    return environ


class VerifiedClientCertificateRequestHandler(WSGIRequestHandler):
    def make_environ(self):
        environ = super().make_environ()
        return inject_verified_client_certificate(
            environ,
            getattr(self, "connection", None),
        )


def create_mtls_server(app, config):
    context = build_mtls_ssl_context(
        config["server_certificate"],
        config["server_private_key"],
        config["client_ca"],
    )
    return make_server(
        config["host"],
        int(config["port"]),
        app,
        threaded=True,
        ssl_context=context,
        request_handler=VerifiedClientCertificateRequestHandler,
    )


def main():
    config = load_mtls_server_config()

    # The Flask collector blueprint reads this during app import.
    os.environ["AEGISGUARD_COLLECTOR_MTLS_REQUIRED"] = "true"

    from backend.analyzer.app import app, debug_print
    from backend.analyzer.database import get_connection
    from backend.analyzer.ingest_worker import (
        start_default_ingest_worker_thread,
    )

    server = create_mtls_server(app, config)

    (
        _ingest_worker,
        ingest_thread,
        ingest_stop_event,
        recovered_batches,
    ) = start_default_ingest_worker_thread(get_connection)

    debug_print(
        "[mTLS SERVER] "
        f"https://{config['host']}:{config['port']} "
        "client_cert_required=True "
        f"recovered={recovered_batches}"
    )

    try:
        server.serve_forever()
    finally:
        ingest_stop_event.set()
        ingest_thread.join(timeout=5)
        server.server_close()


if __name__ == "__main__":
    main()
