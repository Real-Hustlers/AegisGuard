"""Distributed benchmark load generator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class GeneratedEvent:
    event_id: int
    source_node: str
    timestamp: str


def generate_events(
    node_name: str,
    count: int,
):
    for index in range(count):
        yield GeneratedEvent(
            event_id=index,
            source_node=node_name,
            timestamp=datetime.now(
                timezone.utc
            ).isoformat(),
        )