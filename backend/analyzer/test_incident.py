from backend.incident_response import IncidentResponse

incident = IncidentResponse()

result = incident.generate_incident(
    prediction="BRUTE_FORCE",
    confidence=97.8
)

print(result)