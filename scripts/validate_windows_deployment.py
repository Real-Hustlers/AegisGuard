"""Run the S10 Windows deployment-source preflight."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(
    __file__
).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from backend.deployment.windows_contract import (  # noqa: E402
    validate_repository,
)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Validate AegisGuard Windows "
            "deployment source hygiene."
        )
    )

    parser.add_argument(
        "--root",
        default=str(PROJECT_ROOT),
        help="AegisGuard repository root",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full report as JSON",
    )

    args = parser.parse_args()

    report = validate_repository(
        Path(args.root)
    )

    if args.json:
        print(
            json.dumps(
                report,
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(
            "AegisGuard S10-A Windows "
            "deployment preflight"
        )
        print(
            f"root={report['root']}"
        )
        print(
            "required_files="
            f"{report['required_file_count']}"
        )
        print(
            f"issues={len(report['issues'])}"
        )

        for issue in report["issues"]:
            print(
                "FAIL "
                f"[{issue['check']}] "
                f"{issue['path']}: "
                f"{issue['message']}"
            )

        if report["ok"]:
            print(
                "PASS: deployment source "
                "contract is clean."
            )

    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
