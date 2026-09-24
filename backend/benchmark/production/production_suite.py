"""Production validation scenario suite."""

from __future__ import annotations

from .validation_runner import run_production_validation


PRODUCTION_SCENARIOS = [
    {
        "name": "enterprise-small",
        "events": 100_000,
        "nodes": 2,
    },
    {
        "name": "enterprise-medium",
        "events": 1_000_000,
        "nodes": 5,
    },
    {
        "name": "enterprise-large",
        "events": 10_000_000,
        "nodes": 10,
    },
]


def run_production_suite():
    results = []

    for scenario in PRODUCTION_SCENARIOS:
        print(
            f"Running {scenario['name']}"
        )

        result = run_production_validation(
            events=scenario["events"],
            nodes=scenario["nodes"],
        )

        result["scenario"] = scenario["name"]

        results.append(result)

    return results