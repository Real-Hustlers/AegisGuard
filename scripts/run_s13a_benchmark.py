from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmarks.s13a import run_benchmark_suite, text_summary, write_report


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Run the reproducible AegisGuard Enterprise S13-A "
            "performance baseline."
        )
    )
    parser.add_argument("--events", type=int, default=1000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--registry-root")
    parser.add_argument(
        "--model-name",
        default="aegis-threat-classifier",
    )
    parser.add_argument("--output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (
        Path(args.output)
        if args.output
        else ROOT / "output" / "benchmarks" / f"s13a-{timestamp}.json"
    )

    report = run_benchmark_suite(
        event_count=args.events,
        batch_size=args.batch_size,
        iterations=args.iterations,
        warmup=args.warmup,
        registry_root=args.registry_root,
        model_name=args.model_name,
    )
    path = write_report(report, output)

    print(text_summary(report))
    print(f"report={path}")
    print(
        "NOTE: These are local benchmark measurements, "
        "not universal AegisGuard performance guarantees."
    )
    return 1 if report["error_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
