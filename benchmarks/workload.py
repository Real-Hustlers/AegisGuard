"""Controlled synthetic workloads for AegisGuard S13-A benchmarks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from backend.analyzer.ml import (
    FEATURE_COLUMNS,
    FEATURE_SCHEMA_VERSION,
    MLEngine,
    ModelRegistry,
)


SYNTHETIC_MODEL_NAME = "s13a-synthetic-rf"
SYNTHETIC_MODEL_VERSION = "benchmark-rf10-v1"

_EVENT_PATTERN = (
    ("FAILED_LOGIN", "HIGH"),
    ("FAILED_LOGIN", "HIGH"),
    ("FAILED_LOGIN", "HIGH"),
    ("LOGON_SUCCESS", "INFO"),
    ("ADMIN_GROUP_ADDED", "HIGH"),
    ("LOCAL_GROUP_ENUMERATION", "INFO"),
    ("PROCESS_CREATED", "HIGH"),
    ("NETWORK_CONNECTION", "HIGH"),
    ("USER_CREATED", "MEDIUM"),
    ("PASSWORD_CHANGED", "LOW"),
    ("FILE_ACCESS", "INFO"),
    ("DEFENDER_ALERT", "CRITICAL"),
)


def generate_records(
    count: int,
    *,
    start_record_id: int = 1,
    hostname: str = "S13A-BENCH-HOST",
) -> list[dict[str, Any]]:
    """Generate deterministic non-customer records."""

    if count < 1:
        raise ValueError("count must be at least 1")

    started = datetime(2026, 1, 1, tzinfo=timezone.utc)
    records = []
    for offset in range(count):
        record_id = start_record_id + offset
        event_type, severity = _EVENT_PATTERN[offset % len(_EVENT_PATTERN)]
        timestamp = started + timedelta(seconds=offset)

        records.append({
            "log_id": f"s13a:{hostname.lower()}:{record_id}",
            "machine_id": "S13A-SYNTHETIC",
            "hostname": hostname,
            "record_id": record_id,
            "os": "Windows-Synthetic",
            "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            "user": "benchmark-user",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "process": (
                "powershell.exe"
                if event_type == "PROCESS_CREATED"
                else None
            ),
            "file_path": "C:/Synthetic/benchmark.dat",
            "severity": severity,
            "raw_log": (
                f"SYNTHETIC_S13A event={event_type} record_id={record_id}"
            ),
            "ml_prediction": None,
            "ml_confidence": None,
            "threat_category": "Synthetic Benchmark",
            "threat_score": 0,
            "threat_level": severity,
        })
    return records


def chunk_records(
    records: Iterable[dict[str, Any]],
    batch_size: int,
) -> list[list[dict[str, Any]]]:
    if batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    values = list(records)
    return [
        values[offset: offset + batch_size]
        for offset in range(0, len(values), batch_size)
    ]


def synthetic_ml_engine() -> tuple[MLEngine, dict[str, Any]]:
    """Build a fixed tiny model for portable benchmark execution."""

    rows = []
    labels = []
    for index in range(12):
        row = {column: 0 for column in FEATURE_COLUMNS}
        if index % 2:
            row["FAILED_LOGIN"] = 4
            row["TOTAL_EVENTS"] = 4
            row["HIGH_EVENTS"] = 4
            row["UNIQUE_USERS"] = 1
            row["UNIQUE_SOURCE_IPS"] = 1
            labels.append("BRUTE_FORCE")
        else:
            row["LOGON_SUCCESS"] = 2
            row["TOTAL_EVENTS"] = 2
            row["UNIQUE_USERS"] = 1
            labels.append("NORMAL")
        rows.append(row)

    features = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    encoder = LabelEncoder()
    encoded = encoder.fit_transform(labels)
    model = RandomForestClassifier(
        n_estimators=10,
        random_state=42,
        n_jobs=1,
    ).fit(features, encoded)

    engine = MLEngine(
        model=model,
        encoder=encoder,
        model_name=SYNTHETIC_MODEL_NAME,
        model_version=SYNTHETIC_MODEL_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )
    return engine, {
        "source": "synthetic_reproducible_model",
        "model_name": engine.model_name,
        "model_version": engine.model_version,
        "feature_schema_version": engine.feature_schema_version,
        "production_model": False,
    }


def resolve_ml_engine(
    *,
    registry_root: str | Path | None = None,
    model_name: str = "aegis-threat-classifier",
) -> tuple[MLEngine, dict[str, Any]]:
    """Use a verified promoted model when explicitly requested."""

    if registry_root is None:
        return synthetic_ml_engine()

    registry = ModelRegistry(registry_root)
    engine = registry.load_promoted_engine(model_name)
    return engine, {
        "source": "promoted_model_registry",
        "model_name": engine.model_name,
        "model_version": engine.model_version,
        "feature_schema_version": engine.feature_schema_version,
        "production_model": True,
        "registry_root": str(Path(registry_root).resolve()),
    }
