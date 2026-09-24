"""Benchmark scenario definitions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BenchmarkScenario:
    name: str
    event_count: int
    description: str


DEFAULT_SCENARIOS = [
    BenchmarkScenario(
        name="small",
        event_count=10_000,
        description="Small validation workload",
    ),
    BenchmarkScenario(
        name="medium",
        event_count=100_000,
        description="Medium enterprise workload",
    ),
    BenchmarkScenario(
        name="large",
        event_count=1_000_000,
        description="Large workload",
    ),
    BenchmarkScenario(
        name="stress",
        event_count=10_000_000,
        description="Stress workload",
    ),
]
