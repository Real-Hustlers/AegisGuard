"""Durable collector-ingest worker primitives.

S2A ends the HTTP request after the complete collector batch is durably
persisted. This worker is the beginning of S2B: it claims persisted batches
outside the request path and records durable success/failure state.

The actual analyzer pipeline is injected as ``processor`` so this module does
not duplicate rule, ML, correlation, or incident behavior. A following S2B
slice will extract the existing analyzer processing path into a reusable
non-Flask function and inject it here.
"""

import threading
import time
from typing import Any, Callable, Dict, Optional

from backend.storage.collector_ingest import (
    claim_next_collector_batch,
    mark_collector_batch_failed,
    mark_collector_batch_processed,
    recover_processing_collector_batches,
    scrub_expired_failed_payloads,
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

    def run_forever(
        self,
        stop_event: Optional[threading.Event] = None,
        poll_interval: float = 1.0,
    ) -> None:
        """Drain queued batches until shutdown.

        Backlog is drained without sleeping. When no work is available, the
        worker waits for ``poll_interval`` or until ``stop_event`` is set.
        Unexpected infrastructure errors are logged and retried instead of
        permanently killing the analyzer's ingest thread.
        """

        if poll_interval < 0:
            raise ValueError("poll_interval must be non-negative")

        while stop_event is None or not stop_event.is_set():
            try:
                result = self.run_once()
            except Exception as exc:
                print(f"[INGEST WORKER] unexpected error: {exc}", flush=True)
                result = None

            if result is not None:
                continue

            if stop_event is not None:
                stop_event.wait(poll_interval)
            else:
                time.sleep(poll_interval)


def build_default_ingest_worker(connection_factory) -> CollectorIngestWorker:
    """Build the production worker with the shared analyzer ingest pipeline."""

    from backend.analyzer.ingest_pipeline import process_collector_payload

    return CollectorIngestWorker(
        connection_factory,
        process_collector_payload,
    )


def recover_interrupted_ingest(connection_factory) -> int:
    """Recover batches left PROCESSING by a previous analyzer process."""

    conn = connection_factory()
    try:
        scrub_expired_failed_payloads(conn)
        return recover_processing_collector_batches(conn)
    finally:
        conn.close()


def start_default_ingest_worker_thread(
    connection_factory,
    poll_interval: float = 1.0,
):
    """Recover interrupted work and start the production ingest worker."""

    recovered = recover_interrupted_ingest(connection_factory)
    worker = build_default_ingest_worker(connection_factory)
    stop_event = threading.Event()
    thread = threading.Thread(
        target=worker.run_forever,
        kwargs={
            "stop_event": stop_event,
            "poll_interval": poll_interval,
        },
        name="aegisguard-collector-ingest",
        daemon=True,
    )
    thread.start()
    return worker, thread, stop_event, recovered
