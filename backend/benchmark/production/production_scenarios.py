"""Production scalability validation scenarios."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ProductionScenario:
    name: str
    events: int
    nodes: int
    description: str


PRODUCTION_SCENARIOS = [
    ProductionScenario(
        name="enterprise-small",
        events=100_000,
        nodes=2,
        description="Small enterprise workload",
    ),
    ProductionScenario(
        name="enterprise-medium",
        events=1_000_000,
        nodes=5,
        description="Medium enterprise workload",
    ),
    ProductionScenario(
        name="enterprise-large",
        events=10_000_000,
        nodes=10,
        description="Large enterprise workload",
    ),
    ProductionScenario(
        name="enterprise-scale",
        events=50_000_000,
        nodes=20,
        description="Production scale workload",
    ),
]