"""Synthetic event generator for scalability benchmarks."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Iterator


def generate_security_events(
    count: int,
) -> Iterator[dict]:
    """
    Generate synthetic security events.

    Used only for performance measurement.
    """

    for index in range(count):
        yield {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "source": "benchmark",

            "event_type": "authentication",

            "action": (
                "login_failed"
                if index % 10 == 0
                else "login_success"
            ),

            "user": {
                "name": f"user_{index % 100}"
            },

            "device": {
                "hostname": (
                    f"endpoint-{index % 1000}"
                )
            },

            "network": {
                "source_ip": (
                    f"192.168.1.{index % 255}"
                )
            },

            "metadata": {
                "benchmark": True,
            },
        }


def generate_json_lines(
    count: int,
) -> Iterator[str]:
    """
    Generate JSONL formatted events.
    """

    for event in generate_security_events(count):
        yield json.dumps(event)