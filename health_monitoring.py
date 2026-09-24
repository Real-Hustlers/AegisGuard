from dataclasses import dataclass

@dataclass
class HealthStatus:
    service: str
    status: str
    message: str = ""

def get_health_status(service: str) -> HealthStatus:
    return HealthStatus(
        service=service,
        status="healthy",
        message="Service operational"
    )
