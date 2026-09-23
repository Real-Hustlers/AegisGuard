"""Read-only asset and collector management API."""

from __future__ import annotations

from flask import Blueprint, jsonify

from backend.storage.collector_inventory import (
    DEFAULT_COLLECTOR_STALE_AFTER_SECONDS,
    CollectorInventoryNotFound,
    get_collector_inventory,
    list_collector_inventory,
)


def create_asset_management_blueprint(
    get_connection,
    *,
    stale_after_seconds=DEFAULT_COLLECTOR_STALE_AFTER_SECONDS,
    clock=None,
):
    """Expose server-authoritative collector inventory."""

    stale_after_seconds = float(
        stale_after_seconds
    )

    if stale_after_seconds <= 0:
        raise ValueError(
            "stale_after_seconds must be greater than zero"
        )

    blueprint = Blueprint(
        "asset_management_api",
        __name__,
    )

    @blueprint.get("/api/collectors")
    def collectors():
        conn = get_connection()

        try:
            items = list_collector_inventory(
                conn,
                now=(
                    clock()
                    if clock is not None
                    else None
                ),
                stale_after_seconds=stale_after_seconds,
            )
        finally:
            conn.close()

        return jsonify({
            "count": len(items),
            "collectors": items,
        })

    @blueprint.get(
        "/api/collectors/<collector_id>"
    )
    def collector_detail(
        collector_id,
    ):
        conn = get_connection()

        try:
            try:
                collector = get_collector_inventory(
                    conn,
                    collector_id,
                    now=(
                        clock()
                        if clock is not None
                        else None
                    ),
                    stale_after_seconds=stale_after_seconds,
                )
            except CollectorInventoryNotFound:
                return jsonify({
                    "error": "collector_not_found",
                    "message": (
                        "collector does not exist"
                    ),
                }), 404
        finally:
            conn.close()

        return jsonify({
            "collector": collector,
        })

    return blueprint
