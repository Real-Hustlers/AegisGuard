"""Enterprise collector ingestion API.

This endpoint provides the S2 durable-ACK boundary. It persists the complete
batch before returning HTTP 202 and deliberately does not run ML, correlation,
or incident generation in the request path.

Per-collector credential enrollment/revocation is introduced in S3. Until then,
deploy this endpoint only behind server-authenticated TLS and trusted network
controls.
"""

from flask import Blueprint, jsonify, request

from backend.storage.collector_ingest import persist_collector_batch


def create_collector_blueprint(connection_factory):
    blueprint = Blueprint("collector_ingest_v1", __name__)

    @blueprint.post("/api/collector/v1/batches")
    def accept_collector_batch():
        payload = request.get_json(silent=True) or {}

        header_collector_id = str(
            request.headers.get("X-AegisGuard-Collector-ID") or ""
        ).strip()
        header_batch_id = str(
            request.headers.get("X-AegisGuard-Batch-ID") or ""
        ).strip()

        if not header_collector_id or not header_batch_id:
            return jsonify({
                "status": "error",
                "message": "collector and batch identity headers are required",
            }), 400

        if str(payload.get("collector_id") or "").strip() != header_collector_id:
            return jsonify({
                "status": "error",
                "message": "collector_id header/body mismatch",
            }), 400

        if str(payload.get("batch_id") or "").strip() != header_batch_id:
            return jsonify({
                "status": "error",
                "message": "batch_id header/body mismatch",
            }), 400

        conn = connection_factory()
        try:
            inserted, state = persist_collector_batch(
                conn,
                payload,
                request.remote_addr,
            )
        except ValueError as exc:
            return jsonify({
                "status": "error",
                "message": str(exc),
            }), 400
        finally:
            conn.close()

        return jsonify({
            "status": "accepted",
            "batch_id": header_batch_id,
            "collector_id": header_collector_id,
            "duplicate": not inserted,
            "analysis_state": state,
        }), 202

    return blueprint
