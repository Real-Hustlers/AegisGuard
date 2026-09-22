"""Read-only Flask API for AegisGuard intelligence snapshots."""

from __future__ import annotations

from typing import Any, Callable

from flask import Blueprint, jsonify, request

from .service import get_intelligence_snapshot


def create_intelligence_blueprint(
    get_connection: Callable[[], Any],
    *,
    snapshot_getter: Callable[..., dict[str, Any]] = get_intelligence_snapshot,
) -> Blueprint:
    """Create the intelligence API without owning app or database lifecycle."""

    blueprint = Blueprint("intelligence_api", __name__)

    @blueprint.get("/api/intelligence")
    def intelligence_snapshot():
        event_limit = request.args.get("event_limit")

        try:
            snapshot = snapshot_getter(
                get_connection,
                event_limit=event_limit,
            )
        except ValueError as exc:
            return jsonify({
                "error": "invalid_event_limit",
                "message": str(exc),
            }), 400

        return jsonify(snapshot)

    return blueprint
