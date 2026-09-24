"""Storage benchmark suite."""

from .storage_runner import run_storage_benchmark
from .storage_reporter import generate_storage_report


SCENARIOS = [
    10000,
    100000,
    1000000,
    10000000,
]


def run_storage_suite():

    results = []

    for count in SCENARIOS:
        print(
            f"Running storage benchmark: {count} events"
        )

        result = run_storage_benchmark(count)

        results.append(result)

    report = generate_storage_report(results)

    print(
        f"Report created: {report}"
    )

    return results