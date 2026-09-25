from dataclasses import dataclass
from typing import Dict

@dataclass
class ValidationReport:
    status: str
    checks: Dict[str, str]

def validate_operations(checks: Dict[str, str]) -> ValidationReport:
    failed = any(v != "PASS" for v in checks.values())
    return ValidationReport(
        status="FAILED" if failed else "VALIDATED",
        checks=checks
    )
