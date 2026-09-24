from dataclasses import dataclass
from typing import Dict

@dataclass
class RecoveryReport:
    component: str
    state: str
    checks: Dict[str, str]

def recover_component(component: str, checks: Dict[str, str]) -> RecoveryReport:
    failed = any(value != "PASS" for value in checks.values())
    return RecoveryReport(
        component=component,
        state="DEGRADED" if failed else "READY",
        checks=checks
    )
