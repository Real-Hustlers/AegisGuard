import json
from pathlib import Path


class PlaybookLoader:

    def __init__(self):
        file_path = Path(__file__).parent / "response_playbooks.json"

        with open(file_path, "r", encoding="utf-8") as file:
            self.playbooks = json.load(file)

    def get_playbook(self, incident_type):
        return self.playbooks.get(
            incident_type,
            {
                "severity": "UNKNOWN",
                "responses": []
            }
        )