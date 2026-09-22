"""Canonical MITRE ATT&CK resolver for AegisGuard Enterprise.

The catalog maps only behaviors that are specific enough to support an ATT&CK
technique. Generic labels such as ``MALWARE`` intentionally resolve to no
technique rather than fabricating attribution from insufficient evidence.
"""

from __future__ import annotations

from backend.analyzer.detection.contracts import MITREMapping


ATTACK_CATALOG_VERSION = "enterprise-attack-2026-05"


def _mapping(technique_id: str, technique: str, tactic: str) -> MITREMapping:
    return MITREMapping(
        technique_id=technique_id,
        technique=technique,
        tactic=tactic,
    )


_LABEL_MAPPINGS: dict[str, tuple[MITREMapping, ...]] = {
    "BRUTE_FORCE": (
        _mapping("T1110", "Brute Force", "Credential Access"),
    ),
    "PRIVILEGE_ESCALATION": (
        _mapping("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    ),
    "USB_ATTACK": (
        _mapping("T1091", "Replication Through Removable Media", "Initial Access"),
        _mapping("T1091", "Replication Through Removable Media", "Lateral Movement"),
    ),
    "USB_THREAT": (
        _mapping("T1091", "Replication Through Removable Media", "Initial Access"),
        _mapping("T1091", "Replication Through Removable Media", "Lateral Movement"),
    ),
    "FILE_TAMPERING": (
        _mapping("T1070", "Indicator Removal", "Stealth"),
    ),
    "FIREWALL_DISABLED": (
        _mapping("T1686", "Disable or Modify System Firewall", "Defense Impairment"),
    ),
    "PORT_SCAN": (
        _mapping("T1046", "Network Service Discovery", "Discovery"),
    ),
    "ACCOUNT_COMPROMISE": (
        _mapping("T1078", "Valid Accounts", "Persistence"),
    ),
    "RANSOMWARE": (
        _mapping("T1486", "Data Encrypted for Impact", "Impact"),
    ),
}


_RULE_MAPPINGS: dict[str, tuple[MITREMapping, ...]] = {
    "AG-RULE-AUTH-001": _LABEL_MAPPINGS["BRUTE_FORCE"],
    "AG-RULE-PRIV-001": _LABEL_MAPPINGS["PRIVILEGE_ESCALATION"],
    # A generic endpoint malware alert does not identify an execution technique.
    "AG-RULE-MALWARE-001": (),
}


_CORRELATION_MAPPINGS: dict[str, tuple[MITREMapping, ...]] = {
    "AG-CORR-AUTH-001A": _LABEL_MAPPINGS["BRUTE_FORCE"],
    "AG-CORR-AUTH-001B": _LABEL_MAPPINGS["BRUTE_FORCE"],
    "AG-CORR-PRIV-001A": (
        _mapping(
            "T1098.007",
            "Account Manipulation: Additional Local or Domain Groups",
            "Privilege Escalation",
        ),
    ),
    "AG-CORR-PRIV-001B": (
        _mapping(
            "T1098.007",
            "Account Manipulation: Additional Local or Domain Groups",
            "Privilege Escalation",
        ),
    ),
    "AG-CORR-DISC-001": (
        _mapping(
            "T1069.001",
            "Permission Groups Discovery: Local Groups",
            "Discovery",
        ),
    ),
    "AG-CORR-PERSIST-001": (
        _mapping("T1136", "Create Account", "Persistence"),
    ),
    "AG-CORR-EXFIL-001": (
        _mapping("T1005", "Data from Local System", "Collection"),
    ),
    "AG-CORR-IMPACT-001": _LABEL_MAPPINGS["RANSOMWARE"],
    # Process + network and generic lateral-movement sequences are not specific
    # enough to assign a technique without stronger evidence.
    "AG-CORR-EXEC-001": (),
    "AG-CORR-LAT-001": (),
}


def _normalize(value: object) -> str:
    return str(value or "").upper().strip()


def mappings_for_label(label: object) -> tuple[MITREMapping, ...]:
    """Return canonical ATT&CK mappings for a classification label."""

    return _LABEL_MAPPINGS.get(_normalize(label), ())


def mappings_for_rule(
    rule_id: object,
    classification_label: object | None = None,
) -> tuple[MITREMapping, ...]:
    """Resolve a deterministic rule, falling back to its classification label."""

    normalized_rule = str(rule_id or "").strip()
    if normalized_rule in _RULE_MAPPINGS:
        return _RULE_MAPPINGS[normalized_rule]
    return mappings_for_label(classification_label)


def mappings_for_correlation(correlation_id: object) -> tuple[MITREMapping, ...]:
    """Resolve a correlation behavior to ATT&CK techniques."""

    return _CORRELATION_MAPPINGS.get(str(correlation_id or "").strip(), ())


def legacy_mapping_for_label(label: object) -> dict[str, str]:
    """Return the legacy single-dictionary shape from the canonical catalog."""

    normalized = _normalize(label)
    if normalized == "NORMAL":
        return {
            "technique_id": "N/A",
            "technique": "No Threat",
            "tactic": "None",
        }

    mappings = mappings_for_label(normalized)
    if not mappings:
        return {
            "technique_id": "N/A",
            "technique": "Unknown",
            "tactic": "Unknown",
        }
    return mappings[0].to_dict()
