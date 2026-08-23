import unittest
from pathlib import Path

from backend.analyzer.response.playbook_loader import get_playbook_resource_path


class PlaybookResourcePathTests(unittest.TestCase):
    def test_source_path_is_the_canonical_repository_resource(self):
        path = get_playbook_resource_path(frozen=False)
        self.assertEqual(path.name, "response_playbooks.json")
        self.assertEqual(path.parent.name, "response")
        self.assertTrue(path.is_file())

    def test_frozen_path_uses_meipass_backend_package_location(self):
        path = get_playbook_resource_path(frozen=True, bundle_root=Path("C:/bundle"))
        self.assertEqual(
            path,
            Path("C:/bundle/backend/analyzer/response/response_playbooks.json"),
        )


if __name__ == "__main__":
    unittest.main()
