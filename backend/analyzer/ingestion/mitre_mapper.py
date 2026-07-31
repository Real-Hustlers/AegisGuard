try:
    from backend.analyzer.ingestion.mitre.mitre_mapper import MitreMapper
except ImportError:
    from .mitre.mitre_mapper import MitreMapper

_mapper = MitreMapper()


def get_mitre_mapping(prediction):
    if not prediction:
        return {
            "technique_id": "Unknown",
            "technique": "Unknown",
            "tactic": "Unknown",
        }

    return _mapper.get_mapping(str(prediction).upper())