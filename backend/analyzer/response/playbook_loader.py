import json
import sys
from pathlib import Path


PLAYBOOK_RESOURCE = Path("backend") / "analyzer" / "response" / "response_playbooks.json"


def get_playbook_resource_path(frozen=None, bundle_root=None):
    """Return the read-only playbook location in source or PyInstaller mode."""
    if frozen is None:
        frozen = getattr(sys, "frozen", False)

    if frozen:
        root = Path(bundle_root) if bundle_root is not None else Path(sys._MEIPASS)
        return root / PLAYBOOK_RESOURCE

    return Path(__file__).resolve().parent / "response_playbooks.json"


class PlaybookLoader:

    def __init__(self):
        file_path = get_playbook_resource_path()

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
