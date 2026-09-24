"""Bounded, secret-safe operational observability for the Analyzer."""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from flask import Blueprint, g, jsonify, request


_OPERATIONAL_LOGGER_NAME = "aegisguard.operational"

# Operational logs are deliberately allow-listed. Request bodies, query
# strings, paths with dynamic identifiers, peer IPs, usernames, hostnames,
# security events, and credentials must not enter this lower-trust stream.
_SAFE_LOG_FIELDS = frozenset({
    "correlation_id",
    "method",
    "endpoint",
    "status_code",
    "duration_ms",
    "outcome",
})


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _configured_logger():
    logger = logging.getLogger(_OPERATIONAL_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not any(
        getattr(handler, "_aegisguard_operational", False)
        for handler in logger.handlers
    ):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        handler._aegisguard_operational = True
        logger.addHandler(handler)

    return logger


def build_operational_event(
    event_name,
    *,
    timestamp_factory: Callable[[], str] = _utc_timestamp,
    **fields,
):
    """Build a bounded JSON-safe operational event.

    Only explicitly approved low-sensitivity fields are retained.
    """

    name = str(event_name or "").strip()
    if not name:
        raise ValueError("event_name is required")
    if len(name) > 128:
        raise ValueError("event_name is too long")

    record = {
        "timestamp": str(timestamp_factory()),
        "service": "aegisguard-analyzer",
        "event_name": name,
    }

    for key in _SAFE_LOG_FIELDS:
        if key not in fields:
            continue

        value = fields[key]

        if key in {"status_code"}:
            record[key] = int(value)
        elif key in {"duration_ms"}:
            record[key] = round(float(value), 3)
        else:
            text = str(value or "").strip()
            record[key] = text or None

    return record


def emit_operational_event(
    event_name,
    *,
    logger=None,
    **fields,
):
    """Emit one compact structured operational event."""

    record = build_operational_event(
        event_name,
        **fields,
    )
    target = logger or _configured_logger()
    target.info(
        json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return record


class OperationalMetrics:
    """Thread-safe bounded process metrics with no high-cardinality labels."""

    def __init__(
        self,
        *,
        monotonic_clock: Callable[[], float] = time.monotonic,
    ):
        self._clock = monotonic_clock
        self._started_at = float(self._clock())
        self._lock = threading.Lock()

        self._requests_total = 0
        self._responses_total = 0
        self._in_flight = 0
        self._responses_by_class = {
            "2xx": 0,
            "3xx": 0,
            "4xx": 0,
            "5xx": 0,
            "other": 0,
        }
        self._latency_sum_ms = 0.0
        self._latency_max_ms = 0.0

    def begin_request(self):
        with self._lock:
            self._requests_total += 1
            self._in_flight += 1

    def finish_request(
        self,
        status_code,
        duration_ms,
    ):
        code = int(status_code)
        duration = max(
            0.0,
            float(duration_ms),
        )

        if 200 <= code < 300:
            bucket = "2xx"
        elif 300 <= code < 400:
            bucket = "3xx"
        elif 400 <= code < 500:
            bucket = "4xx"
        elif 500 <= code < 600:
            bucket = "5xx"
        else:
            bucket = "other"

        with self._lock:
            self._responses_total += 1
            self._in_flight = max(
                0,
                self._in_flight - 1,
            )
            self._responses_by_class[bucket] += 1
            self._latency_sum_ms += duration
            self._latency_max_ms = max(
                self._latency_max_ms,
                duration,
            )

    def snapshot(self):
        with self._lock:
            responses = self._responses_total
            average = (
                self._latency_sum_ms / responses
                if responses
                else 0.0
            )
            uptime = max(
                0.0,
                float(self._clock()) - self._started_at,
            )

            return {
                "uptime_seconds": round(uptime, 3),
                "requests_total": self._requests_total,
                "responses_total": responses,
                "in_flight": self._in_flight,
                "responses_by_class": dict(
                    self._responses_by_class
                ),
                "latency_ms": {
                    "average": round(average, 3),
                    "maximum": round(
                        self._latency_max_ms,
                        3,
                    ),
                },
            }


def install_operational_observability(
    app,
    metrics: OperationalMetrics,
    *,
    event_emitter: Optional[Callable] = None,
    monotonic_clock: Callable[[], float] = time.monotonic,
):
    """Instrument request completion without collecting request content."""

    emitter = event_emitter or emit_operational_event

    @app.before_request
    def begin_operational_observation():
        metrics.begin_request()
        g.aegisguard_observation_started_at = float(
            monotonic_clock()
        )
        g.aegisguard_observation_finished = False

    @app.after_request
    def finish_operational_observation(response):
        started = getattr(
            g,
            "aegisguard_observation_started_at",
            None,
        )
        if (
            started is not None
            and not getattr(
                g,
                "aegisguard_observation_finished",
                False,
            )
        ):
            duration_ms = max(
                0.0,
                (
                    float(monotonic_clock())
                    - float(started)
                )
                * 1000.0,
            )
            metrics.finish_request(
                response.status_code,
                duration_ms,
            )
            g.aegisguard_observation_finished = True

            emitter(
                "http.request.completed",
                correlation_id=getattr(
                    g,
                    "aegisguard_correlation_id",
                    None,
                ),
                method=request.method.upper(),
                endpoint=request.endpoint or "unmatched",
                status_code=response.status_code,
                duration_ms=duration_ms,
                outcome=(
                    "success"
                    if response.status_code < 400
                    else "failure"
                ),
            )

        return response

    @app.teardown_request
    def close_unfinished_observation(_error):
        started = getattr(
            g,
            "aegisguard_observation_started_at",
            None,
        )
        if (
            started is None
            or getattr(
                g,
                "aegisguard_observation_finished",
                False,
            )
        ):
            return None

        duration_ms = max(
            0.0,
            (
                float(monotonic_clock())
                - float(started)
            )
            * 1000.0,
        )
        metrics.finish_request(
            500,
            duration_ms,
        )
        g.aegisguard_observation_finished = True

        emitter(
            "http.request.aborted",
            correlation_id=getattr(
                g,
                "aegisguard_correlation_id",
                None,
            ),
            method=request.method.upper(),
            endpoint=request.endpoint or "unmatched",
            status_code=500,
            duration_ms=duration_ms,
            outcome="failure",
        )

    return begin_operational_observation


def _safe_readiness(readiness_provider):
    try:
        report = readiness_provider()
        if isinstance(report, dict):
            return report
    except Exception:
        pass

    return {
        "service": "aegisguard-analyzer",
        "status": "not_ready",
        "checks": {
            "readiness_probe": {
                "ok": False,
                "reason": "readiness_probe_failed",
            },
        },
    }


def create_operational_observability_blueprint(
    metrics: OperationalMetrics,
    readiness_provider,
    *,
    runtime_mode: str,
):
    """Create administrator-governed operational visibility endpoints."""

    blueprint = Blueprint(
        "operational_observability",
        __name__,
    )

    @blueprint.route(
        "/api/operations/metrics",
        methods=["GET"],
    )
    def operational_metrics():
        return jsonify({
            "service": "aegisguard-analyzer",
            "status": "ok",
            "metrics": metrics.snapshot(),
        })

    @blueprint.route(
        "/api/operations/diagnostics",
        methods=["GET"],
    )
    def operational_diagnostics():
        return jsonify({
            "service": "aegisguard-analyzer",
            "runtime_mode": str(runtime_mode),
            "readiness": _safe_readiness(
                readiness_provider
            ),
            "metrics": metrics.snapshot(),
        })

    return blueprint
