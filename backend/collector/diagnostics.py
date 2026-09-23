"""Secret-safe diagnostic formatting for the AegisGuard collector."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

try:
    from backend.platform.data_privacy import (
        redact_sensitive_mapping,
        redact_sensitive_text,
    )
except ImportError:
    # Preserve direct-script collector compatibility from the repository tree.
    repo_root = Path(__file__).resolve().parents[2]
    repo_root_text = str(repo_root)
    if repo_root_text not in sys.path:
        sys.path.insert(0, repo_root_text)
    from backend.platform.data_privacy import (
        redact_sensitive_mapping,
        redact_sensitive_text,
    )


def sanitize_diagnostic(value, *, max_length: int = 2048) -> str:
    """Return diagnostic text with secret-bearing fields removed."""

    if isinstance(value, Mapping):
        safe_value = redact_sensitive_mapping(value)
        serialized = json.dumps(
            safe_value,
            sort_keys=True,
            default=str,
        )
        return redact_sensitive_text(
            serialized,
            max_length=max_length,
        )

    if isinstance(value, (list, tuple)):
        wrapped = redact_sensitive_mapping(
            {"items": list(value)}
        )
        serialized = json.dumps(
            wrapped["items"],
            sort_keys=True,
            default=str,
        )
        return redact_sensitive_text(
            serialized,
            max_length=max_length,
        )

    return redact_sensitive_text(
        value,
        max_length=max_length,
    )


def sanitize_http_response(response, *, max_length: int = 2048) -> str:
    """Sanitize an HTTP response body before it is written to diagnostics."""

    try:
        body = response.json()
    except (TypeError, ValueError):
        body = getattr(response, "text", "")

    return sanitize_diagnostic(
        body,
        max_length=max_length,
    )


def sanitize_url_for_diagnostics(value) -> str:
    """Drop URL credentials, query strings, and fragments from diagnostics."""

    try:
        parsed = urlsplit(str(value or ""))
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
        return urlunsplit(
            (
                parsed.scheme,
                host,
                parsed.path,
                "",
                "",
            )
        )
    except (TypeError, ValueError):
        return "[INVALID URL]"
