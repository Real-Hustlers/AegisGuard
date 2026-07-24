MITRE_MAP = {
    "BRUTE_FORCE": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    "PRIVILEGE_ESCALATION": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
    },
    "MALWARE": {
        "technique_id": "T1204",
        "technique_name": "User Execution",
        "tactic": "Execution",
    },
    "RANSOMWARE": {
        "technique_id": "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic": "Impact",
    },
    "NORMAL": {
        "technique_id": "N/A",
        "technique_name": "No Threat",
        "tactic": "None",
    },
}


def get_mitre_mapping(prediction):
    if not prediction:
        return {
            "technique_id": "Unknown",
            "technique_name": "Unknown",
            "tactic": "Unknown",
        }

    normalized = str(prediction).upper()
    mapping = MITRE_MAP.get(normalized)
    if mapping:
        return mapping

    return {
        "technique_id": "Unknown",
        "technique_name": "Unknown",
        "tactic": "Unknown",
    }
