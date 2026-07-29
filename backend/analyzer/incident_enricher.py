from backend.analyzer.ingestion.mitre.mitre_mapper import MitreMapper
from response.playbook_loader import PlaybookLoader

class IncidentEnricher:

    def __init__(self):
        self.mitre = MitreMapper()
        self.playbook = PlaybookLoader()

    def enrich(self, incident):
        """
        Adds MITRE ATT&CK mapping and response playbook
        to an existing incident dictionary.
        """

        prediction = incident["ml_prediction"]

        incident["mitre"] = self.mitre.get_mapping(prediction)
        incident["playbook"] = self.playbook.get_playbook(prediction)

        return incident