"""Distributed benchmark suite."""

from .scenarios import DEFAULT_DISTRIBUTED_SCENARIOS
from .distributed_runner import run_distributed_benchmark


def run_distributed_suite():

    results = []

    for scenario in DEFAULT_DISTRIBUTED_SCENARIOS:

        print(
            f"Running {scenario.name}: "
            f"{scenario.nodes} nodes"
        )

        result = run_distributed_benchmark(
            nodes=scenario.nodes,
            events_per_node=scenario.events_per_node,
        )

        result["scenario"] = scenario.name

        results.append(result)

    return results