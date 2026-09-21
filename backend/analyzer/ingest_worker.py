"""Durable collector-ingest worker primitives.

S2A ends the HTTP request after the complete collector batch is durably
persisted. This worker is the beginning of S2B: it claims persisted batches
outside the request path and records durable success/failure state.

The actual analyzer pipeline is injected as ``processor`` so this module does
not duplicate rule, ML, correlation, or incident behavior. A following S2B
slice will extract the existing analyzer processing path into a reusable
non-Flask function and inject it here.
"""

from typing import Any, Callable, Dict, Optional

from backend.storage.collector_ingest import (
    claim_next_collector_batch,
    mark_collector_batch_failed,
    mark_collector_batch_processed,
)

Processor = Callable[[Dict[str, Any], Optional[str]], Any]


class CollectorIngestWorker:
    """Claim and process one durable collector batch at a time."""

    def __init__(self, connection_factory, processor: Processor):
        self.connection_factory = connection_factory
        self.processor = processor

    def run_once(self) -> Optional[Dict[str, Any]]:
        """Process at most one queued batch."""
        conn = self.connection_factory()
        try:
            batch = claim_next_collector_batch(conn)
        finally:
            conn.close()

        if batch is None:
            return None

        batch_id = batch["batch_id"]
        try:
            result = self.processor(batch["payload"], batch.get("peer_ip"))
        except Exception as exc:
            conn = self.connection_factory()
            try:
                updated = mark_collector_batch_failed(conn, batch_id, str(exc))
            finally:
                conn.close()
            if not updated:
                raise RuntimeError(
                    f"batch {batch_id} left PROCESSING state before failure could be recorded"
                ) from exc
            return {
                "batch_id": batch_id,
                "state": "FAILED",
                "attempts": batch["attempts"],
                "error": str(exc),
            }

        conn = self.connection_factory()
        try:
            updated = mark_collector_batch_processed(conn, batch_id)
        finally:
            conn.close()
        if not updated:
            raise RuntimeError(
                f"batch {batch_id} left PROCESSING state before success could be recorded"
            )
        return {
            "batch_id": batch_id,
            "state": "PROCESSED",
            "attempts": batch["attempts"],
            "result": result,
        }
