try:
    from backend.analyzer.ingestion.mitre.mitre_mapper import MitreMapper
except ImportError:
    from .mitre.mitre_mapper import MitreMapper

_mapper = MitreMapper()


def get_mitre_mapping(prediction):
    return _mapper.get_mapping(prediction)
