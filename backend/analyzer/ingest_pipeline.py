"""Shared non-Flask collector ingestion pipeline.

This module owns the analyzer work that must be identical whether an event
arrives through the legacy live-upload route or through the S2 durable ingest
worker.  It deliberately contains no Flask request/response handling and no
queue state transitions.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Set


@dataclass(frozen=True)
class IngestDependencies:
    """Injectable analyzer dependencies used by the shared ingest pipeline."""

    build_log_identity: Callable[[Dict[str, Any]], str]
    get_existing_log_ids: Callable[[Iterable[Dict[str, Any]]], Set[str]]
    classify_records: Callable[[Iterable[Dict[str, Any]]], list]
    insert_new_security_logs: Callable[[Iterable[Dict[str, Any]]], list]
    record_collector_endpoint: Callable[[str, str], None]
    get_connection: Callable[[], Any]
    scan_and_generate_incidents: Callable[[Any], int]


def _default_dependencies() -> IngestDependencies:
    """Load production dependencies lazily.

    Lazy loading keeps the worker primitive importable without deserializing
    model artifacts or importing Flask application state.
    """

    try:
        from backend.analyzer.database import (
            build_log_identity,
            get_connection,
            get_existing_log_ids,
            insert_new_security_logs,
            record_collector_endpoint,
        )
    except ImportError:
        from database import (
            build_log_identity,
            get_connection,
            get_existing_log_ids,
            insert_new_security_logs,
            record_collector_endpoint,
        )

    try:
        from backend.analyzer.ingestion.classifier import classify_records
    except ImportError:
        from ingestion.classifier import classify_records

    try:
        from backend.analyzer import incident_response
    except ImportError:
        import incident_response

    return IngestDependencies(
        build_log_identity=build_log_identity,
        get_existing_log_ids=get_existing_log_ids,
        classify_records=classify_records,
        insert_new_security_logs=insert_new_security_logs,
        record_collector_endpoint=record_collector_endpoint,
        get_connection=get_connection,
        scan_and_generate_incidents=incident_response.scan_and_generate_incidents,
    )


def normalize_collector_payload(payload: Dict[str, Any]):
    """Normalize one Collector payload without touching historical files."""

    logs = payload.get("logs", [])
    if not isinstance(logs, list):
        raise ValueError("'logs' must be a list")

    machine_id = str(
        payload.get("machine_id") or payload.get("hostname") or "UNKNOWN"
    )
    hostname = str(payload.get("hostname") or machine_id)
    operating_system = str(payload.get("os") or "Windows")
    normalized = []

    for raw in logs:
        if not isinstance(raw, dict):
            continue

        record_id = raw.get("record_id", raw.get("RecordId"))
        normalized.append({
            "machine_id": str(raw.get("machine_id") or machine_id),
            "hostname": str(
                raw.get("hostname") or raw.get("MachineName") or hostname
            ),
            "os": str(raw.get("os") or operating_system),
            "record_id": record_id,
            "timestamp": raw.get("timestamp") or raw.get("TimeCreated") or "",
            "event_type": str(
                raw.get("event_type")
                or raw.get("event_id")
                or raw.get("Id")
                or "OTHER"
            ).upper(),
            "user": raw.get("user") or raw.get("User") or "",
            "source_ip": raw.get("source_ip") or raw.get("SourceIp") or "",
            "destination_ip": (
                raw.get("destination_ip") or raw.get("DestinationIp") or ""
            ),
            "process": raw.get("process") or raw.get("ProcessName") or "",
            "file_path": raw.get("file_path") or raw.get("FilePath") or "",
            "severity": raw.get("severity") or raw.get("LevelDisplayName") or "INFO",
            "raw_log": raw.get("raw_log") or raw.get("Message") or "",
        })

    return machine_id, normalized


def process_normalized_collector_logs(
    machine_id: str,
    normalized,
    collector_ip: Optional[str] = None,
    dependencies: Optional[IngestDependencies] = None,
) -> Dict[str, Any]:
    """Run retry-safe analyzer processing for an already normalized batch."""

    deps = dependencies or _default_dependencies()

    if collector_ip:
        deps.record_collector_endpoint(machine_id, collector_ip)

    existing_ids = deps.get_existing_log_ids(normalized)
    pending = []
    pending_ids = set()

    for log in normalized:
        identity = deps.build_log_identity(log)
        if identity in existing_ids or identity in pending_ids:
            continue
        pending_ids.add(identity)
        pending.append(log)

    classified = deps.classify_records(pending) if pending else []
    inserted = deps.insert_new_security_logs(classified)

    incidents_created = 0
    if inserted:
        conn = deps.get_connection()
        try:
            incidents_created = int(deps.scan_and_generate_incidents(conn) or 0)
        finally:
            conn.close()

    return {
        "machine": machine_id,
        "logs_received": len(normalized),
        "new_logs_added": len(inserted),
        "inserted_log_ids": [
            str(log.get("log_id"))
            for log in inserted
            if log.get("log_id") not in (None, "")
        ],
        "incidents_created": incidents_created,
    }


def process_collector_payload(
    payload: Dict[str, Any],
    collector_ip: Optional[str] = None,
    dependencies: Optional[IngestDependencies] = None,
) -> Dict[str, Any]:
    """Normalize and process a Collector payload outside Flask/HTTP state."""

    machine_id, normalized = normalize_collector_payload(payload)
    return process_normalized_collector_logs(
        machine_id,
        normalized,
        collector_ip,
        dependencies,
    )
