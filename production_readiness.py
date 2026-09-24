from dataclasses import dataclass
from typing import Dict

@dataclass
class ReadinessReport:
    status: str
    checks: Dict[str, str]

def validate_readiness(checks: Dict[str, str]) -> ReadinessReport:
    failed = any(v != "PASS" for v in checks.values())
    return ReadinessReport(
        status="DEGRADED" if failed else "READY",
        checks=checks
    )
