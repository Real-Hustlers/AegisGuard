"""Durable Windows collector runtime.

The live Windows collector writes every parsed batch to local SQLite before
network delivery. A batch leaves the spool only after the analyzer returns the
exact durable HTTP 202 acknowledgement for that collector_id and batch_id.
"""

from pathlib import Path
from typing import Callable, Optional

import requests

from backend.collector.state import CollectorState
from backend.collector.transport import (
    build_batch_payload,
    send_batch,
    validate_analyzer_url,
    validate_batch_ack,
)


class DurableCollectorRuntime:
    """Own durable collector identity, spool delivery, and ACK checkpointing."""

    def __init__(
        self,
        state: CollectorState,
        analyzer_url: str,
        ca_bundle=None,
        hostname: str = "",
        os_name: str = "",
        sender: Callable = send_batch,
        ack_validator: Callable = validate_batch_ack,
    ):
        validate_analyzer_url(analyzer_url)
        self.state = state
        self.analyzer_url = analyzer_url
        self.ca_bundle = ca_bundle
        self.hostname = str(hostname)
        self.os_name = str(os_name)
        self.sender = sender
        self.ack_validator = ack_validator
        self.collector_id = state.get_or_create_collector_id()

    @classmethod
    def from_config(cls, config, config_path, hostname: str, os_name: str):
        """Build the runtime without creating state during module import."""

        analyzer_url = str(config.get("collector_ingest_url") or "").strip()
        if not analyzer_url:
            raise ValueError("collector_ingest_url is required")

        config_path = Path(config_path)
        state_path = Path(
            str(config.get("collector_state_file") or "collector_state.db")
        )
        if not state_path.is_absolute():
            state_path = config_path.parent / state_path

        ca_bundle = config.get("ca_bundle")
        if ca_bundle:
            ca_path = Path(str(ca_bundle))
            if not ca_path.is_absolute():
                ca_path = config_path.parent / ca_path
            ca_bundle = str(ca_path)

        return cls(
            CollectorState(state_path),
            analyzer_url,
            ca_bundle=ca_bundle,
            hostname=hostname,
            os_name=os_name,
        )

    def initialize(
        self,
        explicit_record: Optional[int],
        latest_record_provider: Callable[[], int],
    ) -> int:
        """Return the restart-safe collection cursor."""

        if self.state.get_checkpoint() is None:
            existing_cursor = self.state.get_collection_cursor()
            if explicit_record is not None:
                baseline = int(explicit_record)
            elif existing_cursor is None:
                baseline = int(latest_record_provider())
            else:
                baseline = 0
            self.state.initialize_checkpoint(baseline)

        return self.collection_cursor()

    def collection_cursor(self) -> int:
        cursor = self.state.get_collection_cursor()
        return int(cursor) if cursor is not None else 0

    def checkpoint(self):
        return self.state.get_checkpoint()

    def enqueue_logs(self, logs, record_ids) -> Optional[str]:
        """Durably spool one parsed batch before any network attempt."""

        if not logs:
            return None

        ids = [int(value) for value in record_ids]
        if not ids:
            raise ValueError("record_ids are required for a non-empty batch")

        payload = build_batch_payload(
            self.collector_id,
            self.hostname,
            self.os_name,
            list(logs),
        )
        return self.state.enqueue(payload, max(ids))

    def flush_pending(self, limit: int = 20) -> bool:
        """Drain the spool in RecordID order until empty or one send fails."""

        if int(limit) < 1:
            raise ValueError("limit must be at least 1")

        while True:
            pending = self.state.pending(limit=int(limit))
            if not pending:
                return True

            for item in pending:
                batch_id = str(item["batch_id"])
                payload = item["payload"]

                try:
                    response = self.sender(
                        self.analyzer_url,
                        payload,
                        timeout=30,
                        ca_bundle=self.ca_bundle,
                    )
                    self.ack_validator(response, payload)
                except (
                    requests.RequestException,
                    ValueError,
                    KeyError,
                    TypeError,
                ) as exc:
                    self.state.mark_attempt(batch_id, str(exc))
                    print(
                        f"[DURABLE UPLOAD] batch={batch_id} failed: {exc}",
                        flush=True,
                    )
                    return False

                self.state.mark_attempt(batch_id, None)
                self.state.acknowledge(batch_id)
                print(
                    f"[DURABLE ACK] batch={batch_id} "
                    f"checkpoint={self.state.get_checkpoint()}",
                    flush=True,
                )
