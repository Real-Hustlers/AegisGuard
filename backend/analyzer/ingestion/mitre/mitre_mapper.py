try:
    from backend.analyzer.mitre import legacy_mapping_for_label
except ImportError:
    from ...mitre import legacy_mapping_for_label


class MitreMapper:
    def get_mapping(self, incident_type):
        return legacy_mapping_for_label(incident_type)
