from pathlib import Path

from benchmarks.measurement import summarize_latencies
from benchmarks.s13a import REPORT_SCHEMA_VERSION, run_benchmark_suite
from benchmarks.workload import generate_records


def test_latency_summary_reports_expected_percentiles():
    summary = summarize_latencies([1.0, 2.0, 3.0, 4.0, 5.0])

    assert summary["min"] == 1.0
    assert summary["p50"] == 3.0
    assert summary["p95"] >= summary["p50"]
    assert summary["p99"] >= summary["p95"]
    assert summary["max"] == 5.0


def test_generated_workload_is_deterministic_and_synthetic():
    first = generate_records(8)
    second = generate_records(8)

    assert first == second
    assert all(
        "SYNTHETIC_S13A" in record["raw_log"]
        for record in first
    )
    assert all(
        record["hostname"] == "S13A-BENCH-HOST"
        for record in first
    )


def test_s13a_smoke_suite_has_separate_component_metrics():
    report = run_benchmark_suite(
        event_count=24,
        batch_size=6,
        iterations=1,
        warmup=0,
    )

    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    assert report["workload"]["synthetic_only"] is True
    assert report["workload"]["event_count"] == 24
    assert report["workload"]["batch_size"] == 6
    assert report["error_count"] == 0

    collector_enqueue = report["metrics"][
        "collector_spool_enqueue"
    ]
    collector_ack = report["metrics"][
        "collector_local_durable_ack"
    ]

    assert collector_enqueue["error_count"] == 0
    assert collector_enqueue["total_units"] == 24
    assert collector_enqueue[
        "throughput_units_per_second"
    ] > 0

    assert collector_ack["error_count"] == 0
    assert collector_ack["total_units"] == 24
    assert collector_ack[
        "throughput_units_per_second"
    ] > 0

    required = {
        "rule_engine",
        "ml_inference",
        "correlation",
        "mitre_projection",
        "attack_story",
        "intelligence_analysis",
        "collector_spool_enqueue",
        "collector_local_durable_ack",
        "collector_api_durable_ack_inprocess",
        "server_durable_queue_persist",
        "server_durable_queue_drain",
        "api_intelligence",
    }
    assert required.issubset(report["metrics"])

    for metric_name in required:
        metric = report["metrics"][metric_name]
        assert metric["error_count"] == 0
        assert metric["latency_ms"]["p50"] >= 0
        assert metric["latency_ms"]["p95"] >= 0
        assert metric["latency_ms"]["p99"] >= 0

    boundary = report["security_boundary"]
    assert boundary["real_customer_logs"] is False
    assert boundary["collector_authentication_modified"] is False
    assert boundary["mtls_modified"] is False
    assert boundary["rbac_modified"] is False
    assert boundary["audit_integrity_modified"] is False
    assert boundary["incident_lifecycle_modified"] is False
    assert boundary["response_execution_invoked"] is False


def test_benchmark_report_captures_reproduction_context():
    report = run_benchmark_suite(
        event_count=12,
        batch_size=6,
        iterations=1,
        warmup=0,
    )

    context = report["context"]
    assert context["python_version"]
    assert "logical_cpu_count" in context
    assert "host_memory_bytes" in context
    assert "dependencies" in context
    assert "scikit-learn" in context["dependencies"]

    assert report["payload"]["intelligence_snapshot_bytes"] > 0
    assert report["storage"]["collector"]["enqueue_storage_bytes"] > 0
    assert (
        report["storage"]["server_queue"]["queued_after_drain"]
        == 0
    )
