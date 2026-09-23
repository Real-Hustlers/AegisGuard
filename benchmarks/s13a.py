"""S13-A reproducible benchmark suite for AegisGuard Enterprise."""

from __future__ import annotations

import io
import json
import sqlite3
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from flask import Flask

from backend.analyzer.collector_api import create_collector_blueprint
from backend.analyzer.correlation import build_attack_stories
from backend.analyzer.correlation.engine import CorrelationEngine
from backend.analyzer.database import ensure_schema
from backend.analyzer.detection.adapters import canonical_event_from_legacy
from backend.analyzer.detection.rule_engine import RuleEngine
from backend.analyzer.ingest_worker import CollectorIngestWorker
from backend.analyzer.intelligence.api import create_intelligence_blueprint
from backend.analyzer.intelligence.ml_runtime import (
    GovernedMLRuntime,
    GovernedMLRuntimeStatus,
)
from backend.analyzer.intelligence.service import (
    _mitre_coverage,
    build_intelligence_snapshot,
)
from backend.collector.durable_runtime import DurableCollectorRuntime
from backend.collector.state import CollectorState
from backend.storage.collector_ingest import persist_collector_batch

from .measurement import measure, reproduction_context
from .workload import chunk_records, generate_records, resolve_ml_engine


REPORT_SCHEMA_VERSION = "aegisguard-s13a-benchmark-v1"


def _sqlite_connection(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(
        str(path),
        timeout=30,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _sqlite_storage_bytes(path: Path) -> int:
    return sum(
        candidate.stat().st_size
        for candidate in (
            path,
            Path(str(path) + "-wal"),
            Path(str(path) + "-shm"),
        )
        if candidate.exists()
    )


def _payload(
    records: list[dict[str, Any]],
    *,
    batch_id: str,
) -> dict[str, Any]:
    return {
        "batch_id": batch_id,
        "collector_id": "s13a-benchmark-collector",
        "hostname": "S13A-BENCH-HOST",
        "os": "Windows-Synthetic",
        "logs": [dict(record) for record in records],
    }


def _insert_api_records(
    conn: sqlite3.Connection,
    records: list[dict[str, Any]],
) -> None:
    conn.execute(
        """
        CREATE TABLE security_logs (
            log_id TEXT PRIMARY KEY,
            timestamp TEXT,
            event_type TEXT,
            severity TEXT,
            hostname TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            user TEXT,
            process TEXT,
            file_path TEXT,
            raw_log TEXT,
            ml_prediction TEXT,
            ml_confidence REAL,
            threat_level TEXT,
            threat_score INTEGER,
            threat_category TEXT
        )
        """
    )
    conn.executemany(
        """
        INSERT INTO security_logs (
            log_id, timestamp, event_type, severity, hostname,
            source_ip, destination_ip, user, process, file_path,
            raw_log, ml_prediction, ml_confidence, threat_level,
            threat_score, threat_category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                record["log_id"],
                record["timestamp"],
                record["event_type"],
                record["severity"],
                record["hostname"],
                record["source_ip"],
                record["destination_ip"],
                record["user"],
                record["process"],
                record["file_path"],
                record["raw_log"],
                record["ml_prediction"],
                record["ml_confidence"],
                record["threat_level"],
                record["threat_score"],
                record["threat_category"],
            )
            for record in records
        ],
    )
    conn.commit()


def _collector_spool_benchmarks(
    batches: list[list[dict[str, Any]]],
    *,
    repetitions: int,
    temp_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    expanded = []
    next_record_id = 1
    for _ in range(repetitions):
        for batch in batches:
            generated = generate_records(
                len(batch),
                start_record_id=next_record_id,
            )
            next_record_id += len(batch)
            expanded.append(generated)

    enqueue_db = temp_root / "collector-enqueue.db"
    enqueue_state = CollectorState(enqueue_db)
    enqueue_runtime = DurableCollectorRuntime(
        enqueue_state,
        "https://127.0.0.1:8443/api/collector/v1/batches",
        hostname="S13A-BENCH-HOST",
        os_name="Windows-Synthetic",
        auth_required=False,
        mtls_required=False,
    )

    def enqueue_operation(index: int) -> int:
        batch = expanded[index]
        record_ids = [int(record["record_id"]) for record in batch]
        enqueue_runtime.enqueue_logs(batch, record_ids)
        return len(batch)

    enqueue_initial_bytes = _sqlite_storage_bytes(enqueue_db)

    enqueue_metric = measure(
        "collector_spool_enqueue",
        enqueue_operation,
        iterations=len(expanded),
        metadata={
            "durability": "collector SQLite spool",
            "sqlite_synchronous": "FULL",
            "real_network": False,
            "unit": "events",
        },
    )
    enqueue_health = enqueue_runtime.health_snapshot()

    ack_db = temp_root / "collector-ack.db"
    ack_state = CollectorState(ack_db)

    def fake_sender(*_args, **_kwargs):
        return object()

    ack_runtime = DurableCollectorRuntime(
        ack_state,
        "https://127.0.0.1:8443/api/collector/v1/batches",
        hostname="S13A-BENCH-HOST",
        os_name="Windows-Synthetic",
        auth_required=False,
        mtls_required=False,
        sender=fake_sender,
        ack_validator=lambda _response, _payload: None,
    )
    ack_initial_bytes = _sqlite_storage_bytes(ack_db)
    next_ack_record_id = 1

    def ack_operation(index: int) -> int:
        nonlocal next_ack_record_id
        size = len(expanded[index])
        batch = generate_records(
            size,
            start_record_id=next_ack_record_id,
        )
        next_ack_record_id += size
        record_ids = [int(record["record_id"]) for record in batch]
        ack_runtime.enqueue_logs(batch, record_ids)
        with redirect_stdout(io.StringIO()):
            flushed = ack_runtime.flush_pending(limit=1)
        if not flushed:
            raise RuntimeError("local durable ACK fixture did not flush")
        return len(batch)

    ack_metric = measure(
        "collector_local_durable_ack",
        ack_operation,
        iterations=len(expanded),
        metadata={
            "real_network": False,
            "server_ack": "synthetic accepted response",
            "measures": (
                "enqueue, attempt bookkeeping, checkpoint advancement, "
                "durable dequeue"
            ),
            "unit": "events",
        },
    )

    enqueue_final_bytes = _sqlite_storage_bytes(enqueue_db)
    ack_final_bytes = _sqlite_storage_bytes(ack_db)

    return enqueue_metric, ack_metric, {
        "enqueue_initial_bytes": enqueue_initial_bytes,
        "enqueue_final_bytes": enqueue_final_bytes,
        "enqueue_growth_bytes": enqueue_final_bytes - enqueue_initial_bytes,
        "enqueue_storage_bytes": enqueue_final_bytes,
        "enqueue_final_health": enqueue_health,
        "ack_initial_bytes": ack_initial_bytes,
        "ack_final_bytes": ack_final_bytes,
        "ack_growth_bytes": ack_final_bytes - ack_initial_bytes,
        "ack_storage_bytes": ack_final_bytes,
        "ack_final_health": ack_runtime.health_snapshot(),
    }


def _collector_api_ack_benchmark(
    batches: list[list[dict[str, Any]]],
    *,
    repetitions: int,
    temp_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    db_path = temp_root / "collector-api.db"

    def connection_factory():
        return _sqlite_connection(db_path)

    conn = connection_factory()
    try:
        ensure_schema(conn)
    finally:
        conn.close()

    initial_bytes = _sqlite_storage_bytes(db_path)

    app = Flask("s13a-collector-api-benchmark")
    app.register_blueprint(
        create_collector_blueprint(
            connection_factory,
            auth_required=False,
            mtls_required=False,
        )
    )
    client = app.test_client()

    payloads = []
    next_record_id = 1
    sequence = 0
    for _ in range(repetitions):
        for batch in batches:
            sequence += 1
            generated = generate_records(
                len(batch),
                start_record_id=next_record_id,
            )
            next_record_id += len(batch)
            payloads.append(
                _payload(
                    generated,
                    batch_id=f"s13a-api-{sequence:08d}",
                )
            )

    def operation(index: int) -> int:
        payload = payloads[index]
        response = client.post(
            "/api/collector/v1/batches",
            json=payload,
            headers={
                "X-AegisGuard-Collector-ID": payload["collector_id"],
                "X-AegisGuard-Batch-ID": payload["batch_id"],
            },
        )
        if response.status_code != 202:
            raise RuntimeError(
                f"collector durable ACK returned HTTP {response.status_code}"
            )
        body = response.get_json() or {}
        if body.get("analysis_state") != "QUEUED":
            raise RuntimeError(
                f"unexpected analysis_state={body.get('analysis_state')}"
            )
        return len(payload["logs"])

    metric = measure(
        "collector_api_durable_ack_inprocess",
        operation,
        iterations=len(payloads),
        metadata={
            "http_boundary": "Flask test client",
            "real_network": False,
            "auth_required_fixture": False,
            "mtls_fixture": False,
            "meaning": (
                "request parsing through durable server-side persistence "
                "and HTTP 202 ACK"
            ),
            "unit": "events",
        },
    )

    conn = connection_factory()
    try:
        queued = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM collector_ingest_batches
                WHERE state = 'QUEUED'
                """
            ).fetchone()[0]
        )
    finally:
        conn.close()

    final_bytes = _sqlite_storage_bytes(db_path)
    return metric, {
        "initial_bytes": initial_bytes,
        "final_bytes": final_bytes,
        "growth_bytes": final_bytes - initial_bytes,
        "database_bytes": final_bytes,
        "queued_after_ack": queued,
    }


def _server_queue_benchmarks(
    batches: list[list[dict[str, Any]]],
    *,
    repetitions: int,
    temp_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    db_path = temp_root / "server-queue.db"

    def connection_factory():
        return _sqlite_connection(db_path)

    conn = connection_factory()
    try:
        ensure_schema(conn)
    finally:
        conn.close()

    initial_bytes = _sqlite_storage_bytes(db_path)

    payloads = []
    next_record_id = 1
    sequence = 0
    for _ in range(repetitions):
        for batch in batches:
            sequence += 1
            generated = generate_records(
                len(batch),
                start_record_id=next_record_id,
            )
            next_record_id += len(batch)
            payloads.append(
                _payload(
                    generated,
                    batch_id=f"s13a-queue-{sequence:08d}",
                )
            )

    def persist_operation(index: int) -> int:
        payload = payloads[index]
        conn = connection_factory()
        try:
            inserted, state = persist_collector_batch(
                conn,
                payload,
                "127.0.0.1",
            )
        finally:
            conn.close()
        if not inserted or state != "QUEUED":
            raise RuntimeError(
                f"unexpected queue result inserted={inserted} state={state}"
            )
        return len(payload["logs"])

    persist_metric = measure(
        "server_durable_queue_persist",
        persist_operation,
        iterations=len(payloads),
        metadata={
            "real_network": False,
            "durable_ack_storage_core": True,
            "unit": "events",
        },
    )

    conn = connection_factory()
    try:
        queued_before = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM collector_ingest_batches
                WHERE state = 'QUEUED'
                """
            ).fetchone()[0]
        )
    finally:
        conn.close()

    worker = CollectorIngestWorker(
        connection_factory,
        lambda payload, _peer_ip: {
            "events": len(payload.get("logs", [])),
        },
    )

    def drain_operation(_index: int) -> int:
        result = worker.run_once()
        if result is None:
            raise RuntimeError("durable queue became empty early")
        processor_result = result.get("result") or {}
        return int(processor_result.get("events") or 0)

    drain_metric = measure(
        "server_durable_queue_drain",
        drain_operation,
        iterations=queued_before,
        metadata={
            "processor": "no-op benchmark processor",
            "analysis": False,
            "meaning": "claim, PROCESSING transition, PROCESSED commit",
            "unit": "events",
        },
    )

    conn = connection_factory()
    try:
        queued_after = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM collector_ingest_batches
                WHERE state = 'QUEUED'
                """
            ).fetchone()[0]
        )
        processed_after = int(
            conn.execute(
                """
                SELECT COUNT(*)
                FROM collector_ingest_batches
                WHERE state = 'PROCESSED'
                """
            ).fetchone()[0]
        )
    finally:
        conn.close()

    final_bytes = _sqlite_storage_bytes(db_path)
    return persist_metric, drain_metric, {
        "initial_bytes": initial_bytes,
        "final_bytes": final_bytes,
        "growth_bytes": final_bytes - initial_bytes,
        "database_bytes": final_bytes,
        "queued_before_drain": queued_before,
        "queued_after_drain": queued_after,
        "processed_after_drain": processed_after,
    }


def _intelligence_api_benchmark(
    records: list[dict[str, Any]],
    ml_engine,
    *,
    iterations: int,
    warmup: int,
    temp_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    db_path = temp_root / "intelligence-api.db"
    conn = _sqlite_connection(db_path)
    try:
        _insert_api_records(conn, records)
    finally:
        conn.close()

    def connection_factory():
        return _sqlite_connection(db_path)

    runtime = GovernedMLRuntime(
        status=GovernedMLRuntimeStatus.AVAILABLE,
        available=True,
        model_name=ml_engine.model_name,
        model_version=ml_engine.model_version,
        feature_schema_version=ml_engine.feature_schema_version,
        engine=ml_engine,
    )

    app = Flask("s13a-intelligence-api-benchmark")
    app.register_blueprint(
        create_intelligence_blueprint(
            connection_factory,
            ml_runtime_provider=lambda: runtime,
        )
    )
    client = app.test_client()
    event_limit = min(len(records), 5000)
    last_payload_bytes = 0

    def operation(_index: int) -> int:
        nonlocal last_payload_bytes
        response = client.get(
            f"/api/intelligence?event_limit={event_limit}"
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"intelligence API returned HTTP {response.status_code}"
            )
        last_payload_bytes = len(response.data)
        return event_limit

    metric = measure(
        "api_intelligence_inprocess",
        operation,
        iterations=iterations,
        warmup=warmup,
        metadata={
            "http_boundary": "Flask test client",
            "real_network": False,
            "rbac_middleware": False,
            "event_limit": event_limit,
            "unit": "events",
        },
    )
    return metric, {
        "database_bytes": _sqlite_storage_bytes(db_path),
        "last_payload_bytes": last_payload_bytes,
    }


def run_benchmark_suite(
    *,
    event_count: int = 1000,
    batch_size: int = 100,
    iterations: int = 5,
    warmup: int = 1,
    registry_root: str | Path | None = None,
    model_name: str = "aegis-threat-classifier",
) -> dict[str, Any]:
    if event_count < 1:
        raise ValueError("event_count must be at least 1")
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    if warmup < 0:
        raise ValueError("warmup must be non-negative")

    records = generate_records(event_count)
    batches = chunk_records(records, batch_size)
    canonical = tuple(
        canonical_event_from_legacy(record)
        for record in records
    )
    ml_engine, model_context = resolve_ml_engine(
        registry_root=registry_root,
        model_name=model_name,
    )

    rule_engine = RuleEngine()
    correlation_engine = CorrelationEngine()
    rule_findings = rule_engine.detect_many(canonical)
    correlation_findings = correlation_engine.correlate(canonical)
    ml_finding = ml_engine.detect(canonical)
    all_findings = (
        tuple(rule_findings)
        + (() if ml_finding is None else (ml_finding,))
        + tuple(correlation_findings)
    )

    metrics = {}

    def rule_operation(_index: int) -> int:
        rule_engine.detect_many(canonical)
        return len(canonical)

    metrics["rule_engine"] = measure(
        "rule_engine",
        rule_operation,
        iterations=iterations,
        warmup=warmup,
        metadata={"engine": rule_engine.engine_name, "unit": "events"},
    )

    def ml_operation(_index: int) -> int:
        ml_engine.detect(canonical)
        return len(canonical)

    metrics["ml_inference"] = measure(
        "ml_inference",
        ml_operation,
        iterations=iterations,
        warmup=warmup,
        metadata={**model_context, "unit": "events"},
    )

    def correlation_operation(_index: int) -> int:
        correlation_engine.correlate(canonical)
        return len(canonical)

    metrics["correlation"] = measure(
        "correlation",
        correlation_operation,
        iterations=iterations,
        warmup=warmup,
        metadata={"engine": correlation_engine.engine_name, "unit": "events"},
    )

    def mitre_operation(_index: int) -> int:
        _mitre_coverage(all_findings)
        return len(all_findings)

    metrics["mitre_projection"] = measure(
        "mitre_projection",
        mitre_operation,
        iterations=iterations,
        warmup=warmup,
        metadata={"input_findings": len(all_findings), "unit": "findings"},
    )

    def story_operation(_index: int) -> int:
        build_attack_stories(all_findings)
        return len(all_findings)

    metrics["attack_story"] = measure(
        "attack_story",
        story_operation,
        iterations=iterations,
        warmup=warmup,
        metadata={"input_findings": len(all_findings), "unit": "findings"},
    )

    def analysis_operation(_index: int) -> int:
        build_intelligence_snapshot(
            records,
            ml_engine=ml_engine,
        )
        return len(records)

    metrics["intelligence_analysis"] = measure(
        "intelligence_analysis",
        analysis_operation,
        iterations=iterations,
        warmup=warmup,
        metadata={
            "includes": [
                "canonicalization",
                "rule",
                "ml",
                "correlation",
                "mitre",
                "attack_story",
                "legacy_telemetry_summary",
            ],
            "persistence": False,
            "unit": "events",
        },
    )

    with tempfile.TemporaryDirectory(
        prefix="aegisguard-s13a-"
    ) as directory:
        temp_root = Path(directory)

        collector_enqueue, collector_ack, collector_storage = (
            _collector_spool_benchmarks(
                batches,
                repetitions=iterations,
                temp_root=temp_root,
            )
        )
        metrics["collector_spool_enqueue"] = collector_enqueue
        metrics["collector_local_durable_ack"] = collector_ack

        api_ack, api_ack_storage = _collector_api_ack_benchmark(
            batches,
            repetitions=iterations,
            temp_root=temp_root,
        )
        metrics["collector_api_durable_ack_inprocess"] = api_ack

        queue_persist, queue_drain, queue_storage = (
            _server_queue_benchmarks(
                batches,
                repetitions=iterations,
                temp_root=temp_root,
            )
        )
        metrics["server_durable_queue_persist"] = queue_persist
        metrics["server_durable_queue_drain"] = queue_drain

        intelligence_api, intelligence_api_storage = (
            _intelligence_api_benchmark(
                records,
                ml_engine,
                iterations=iterations,
                warmup=warmup,
                temp_root=temp_root,
            )
        )
        metrics["api_intelligence"] = intelligence_api

        storage = {
            "collector": collector_storage,
            "collector_api": api_ack_storage,
            "server_queue": queue_storage,
            "intelligence_api": intelligence_api_storage,
        }

    snapshot = build_intelligence_snapshot(
        records,
        ml_engine=ml_engine,
    )
    serialized_snapshot = json.dumps(
        snapshot,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    dataset_json = json.dumps(
        records,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")

    error_count = sum(
        int(metric.get("error_count", 0))
        for metric in metrics.values()
    )

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "context": reproduction_context(),
        "workload": {
            "synthetic_only": True,
            "event_count": event_count,
            "dataset_bytes": len(dataset_json),
            "batch_size": batch_size,
            "batch_count": len(batches),
            "iterations": iterations,
            "warmup_iterations": warmup,
            "event_pattern_size": 12,
        },
        "model": model_context,
        "metrics": metrics,
        "payload": {
            "intelligence_snapshot_bytes": len(serialized_snapshot),
            "intelligence_snapshot_kib": round(
                len(serialized_snapshot) / 1024.0,
                3,
            ),
        },
        "storage": storage,
        "security_boundary": {
            "real_customer_logs": False,
            "collector_authentication_modified": False,
            "mtls_modified": False,
            "rbac_modified": False,
            "audit_integrity_modified": False,
            "incident_lifecycle_modified": False,
            "response_execution_invoked": False,
            "real_network_tls_benchmark": False,
            "note": (
                "S13-A uses isolated local durable stores and in-process Flask "
                "boundaries. Real network/mTLS cost is intentionally deferred "
                "to the authorized S11/S13-B environment."
            ),
        },
        "error_count": error_count,
    }


def write_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    return path


def text_summary(report: dict[str, Any]) -> str:
    workload = report["workload"]
    lines = [
        "AegisGuard S13-A local benchmark",
        (
            f"events={workload['event_count']} "
            f"dataset_bytes={workload['dataset_bytes']} "
            f"batch_size={workload['batch_size']} "
            f"batches={workload['batch_count']} "
            f"iterations={workload['iterations']}"
        ),
    ]

    for key, metric in report["metrics"].items():
        latency = metric["latency_ms"]
        unit = metric.get("metadata", {}).get("unit", "units")
        lines.append(
            f"{key}: "
            f"throughput={metric['throughput_units_per_second']:.3f} {unit}/s "
            f"p50={latency['p50']:.4f}ms "
            f"p95={latency['p95']:.4f}ms "
            f"p99={latency['p99']:.4f}ms "
            f"errors={metric['error_count']}"
        )

    lines.append(
        "intelligence_payload="
        f"{report['payload']['intelligence_snapshot_bytes']} bytes"
    )
    lines.append(f"errors={report['error_count']}")
    return "\n".join(lines)
