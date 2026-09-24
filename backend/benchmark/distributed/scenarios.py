"""Distributed benchmark scenarios."""

from dataclasses import dataclass


@dataclass
class DistributedScenario:
    name: str
    nodes: int
    events_per_node: int
    description: str


DEFAULT_DISTRIBUTED_SCENARIOS = [

    DistributedScenario(
        name="small-cluster",
        nodes=2,
        events_per_node=100_000,
        description="Two collector nodes",
    ),

    DistributedScenario(
        name="medium-cluster",
        nodes=5,
        events_per_node=100_000,
        description="Enterprise collector cluster",
    ),

    DistributedScenario(
        name="large-cluster",
        nodes=10,
        events_per_node=100_000,
        description="Large distributed deployment",
    ),

    DistributedScenario(
        name="stress-cluster",
        nodes=20,
        events_per_node=100_000,
        description="High scale collector deployment",
    ),
]