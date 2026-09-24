import json
import logging

from flask import Flask, jsonify

from backend.analyzer.app_authorization import (
    ROLE_ADMINISTRATOR,
    required_roles_for_request,
)
from backend.analyzer.operational_observability import (
    OperationalMetrics,
    build_operational_event,
    create_operational_observability_blueprint,
    install_operational_observability,
)


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


def test_operational_event_is_allowlisted_and_drops_sensitive_input():
    event = build_operational_event(
        "http.request.completed",
        timestamp_factory=lambda: "2026-09-24T00:00:00+00:00",
        correlation_id="req-123",
        method="POST",
        endpoint="incident_transition",
        status_code=200,
        duration_ms=12.34567,
        password="do-not-log",
        peer_ip="10.0.0.8",
        raw_log="sensitive event",
        query_string="token=secret",
    )

    serialized = json.dumps(event)

    assert event["event_name"] == "http.request.completed"
    assert event["correlation_id"] == "req-123"
    assert event["duration_ms"] == 12.346

    for forbidden in (
        "do-not-log",
        "10.0.0.8",
        "sensitive event",
        "token=secret",
        "password",
        "peer_ip",
        "raw_log",
        "query_string",
    ):
        assert forbidden not in serialized


def test_metrics_are_bounded_aggregate_counts_without_route_labels():
    clock = iter([100.0, 105.0])
    metrics = OperationalMetrics(
        monotonic_clock=lambda: next(clock)
    )

    metrics.begin_request()
    metrics.finish_request(
        200,
        10.0,
    )
    metrics.begin_request()
    metrics.finish_request(
        503,
        30.0,
    )

    snapshot = metrics.snapshot()

    assert snapshot["uptime_seconds"] == 5.0
    assert snapshot["requests_total"] == 2
    assert snapshot["responses_total"] == 2
    assert snapshot["in_flight"] == 0
    assert snapshot["responses_by_class"]["2xx"] == 1
    assert snapshot["responses_by_class"]["5xx"] == 1
    assert snapshot["latency_ms"]["average"] == 20.0
    assert snapshot["latency_ms"]["maximum"] == 30.0

    serialized = json.dumps(snapshot)
    for forbidden in (
        "path",
        "endpoint",
        "user",
        "peer_ip",
        "hostname",
        "source_ip",
    ):
        assert forbidden not in serialized


def test_request_observability_uses_server_correlation_without_request_content():
    app = Flask(__name__)
    metrics = OperationalMetrics()

    captured = []

    @app.before_request
    def server_correlation():
        from flask import g
        g.aegisguard_correlation_id = "req-server-generated"

    install_operational_observability(
        app,
        metrics,
        event_emitter=lambda event_name, **fields: captured.append(
            (event_name, fields)
        ),
    )

    @app.route("/example/<item_id>", methods=["POST"])
    def example(item_id):
        return jsonify({"ok": True})

    client = app.test_client()
    response = client.post(
        "/example/secret-object-id?token=secret-query",
        json={
            "password": "secret-password",
        },
    )

    assert response.status_code == 200
    assert len(captured) == 1

    event_name, fields = captured[0]
    assert event_name == "http.request.completed"
    assert fields["correlation_id"] == "req-server-generated"
    assert fields["endpoint"] == "example"
    assert fields["method"] == "POST"

    serialized = json.dumps(captured)
    assert "secret-object-id" not in serialized
    assert "secret-query" not in serialized
    assert "secret-password" not in serialized


def test_operational_endpoints_are_administrator_only():
    for path in (
        "/api/operations/metrics",
        "/api/operations/diagnostics",
    ):
        assert required_roles_for_request(
            path,
            "GET",
        ) == frozenset({
            ROLE_ADMINISTRATOR,
        })


def test_operational_blueprint_reports_metrics_and_safe_diagnostics():
    app = Flask(__name__)
    metrics = OperationalMetrics()

    app.register_blueprint(
        create_operational_observability_blueprint(
            metrics,
            lambda: {
                "service": "aegisguard-analyzer",
                "status": "ready",
                "checks": {
                    "database": {
                        "ok": True,
                        "reason": None,
                    },
                },
            },
            runtime_mode="source",
        )
    )

    client = app.test_client()

    metrics_response = client.get(
        "/api/operations/metrics"
    )
    diagnostics_response = client.get(
        "/api/operations/diagnostics"
    )

    assert metrics_response.status_code == 200
    assert diagnostics_response.status_code == 200

    metrics_payload = metrics_response.get_json()
    diagnostics_payload = diagnostics_response.get_json()

    assert metrics_payload["service"] == "aegisguard-analyzer"
    assert "metrics" in metrics_payload

    assert diagnostics_payload["runtime_mode"] == "source"
    assert diagnostics_payload["readiness"]["status"] == "ready"

    serialized = json.dumps(diagnostics_payload)
    for forbidden in (
        "database_path",
        "raw_log",
        "password",
        "peer_ip",
        "username",
    ):
        assert forbidden not in serialized


def test_readiness_probe_failure_is_generic_and_does_not_leak_exception():
    app = Flask(__name__)
    metrics = OperationalMetrics()

    def broken_probe():
        raise RuntimeError(
            "password=top-secret database=C:/private/aegisguard.db"
        )

    app.register_blueprint(
        create_operational_observability_blueprint(
            metrics,
            broken_probe,
            runtime_mode="frozen",
        )
    )

    response = app.test_client().get(
        "/api/operations/diagnostics"
    )

    payload = response.get_json()
    serialized = json.dumps(payload)

    assert payload["readiness"]["status"] == "not_ready"
    assert (
        payload["readiness"]["checks"]["readiness_probe"]["reason"]
        == "readiness_probe_failed"
    )
    assert "top-secret" not in serialized
    assert "C:/private" not in serialized
