import json
from pathlib import Path


class MitreMapper:

    def __init__(self):
        file_path = Path(__file__).parent / "mitre_mapping.json"

        with open(file_path, "r", encoding="utf-8") as file:
            self.mapping = json.load(file)

    def get_mapping(self, incident_type):
        return self.mapping.get(
            incident_type,
            {
                "tactic": "Unknown",
                "technique": "Unknown",
                "technique_id": "N/A"
            }
        )