"""Benchmark data models for AegisGuard scalability validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class BenchmarkConfig:
    """Defines a benchmark execution."""

    name: str
    event_count: int
    description: str = ""


@dataclass
class ResourceSnapshot:
    """System resource measurement."""

    cpu_percent: float = 0.0
    memory_mb: float = 0.0


@dataclass
class BenchmarkResult:
    """Stores benchmark execution output."""

    benchmark_name: str
    total_events: int

    start_time: datetime
    end_time: datetime

    processing_seconds: float
    events_per_second: float

    average_latency_ms: float

    resources: ResourceSnapshot = field(
        default_factory=ResourceSnapshot
    )

    success: bool = True

    def to_dict(self) -> dict:
        return {
            "benchmark_name": self.benchmark_name,
            "total_events": self.total_events,
            "processing_seconds": self.processing_seconds,
            "events_per_second": self.events_per_second,
            "average_latency_ms": self.average_latency_ms,
            "resources": {
                "cpu_percent": self.resources.cpu_percent,
                "memory_mb": self.resources.memory_mb,
            },
            "success": self.success,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
        }