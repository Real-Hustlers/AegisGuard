"""Policy and target validation for the AegisGuard SOAR engine."""

import ipaddress
import json
import os
import socket


DEFAULT_ALLOWLIST = {"127.0.0.1", "::1"}


def _truthy(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def analyzer_ip_addresses():
    """Best-effort local addresses; failure must not make a target safe."""
    addresses = set()
    try:
        for item in socket.getaddrinfo(socket.gethostname(), None):
            addresses.add(item[4][0].split("%")[0])
    except OSError:
        pass
    return addresses


class ResponsePolicy:
    def __init__(self, settings=None, self_ips=None):
        settings = settings or {}
        self.mode = str(settings.get("soar_mode", os.getenv("SOAR_MODE", "MANUAL"))).upper()
        self.mode = self.mode if self.mode in {"OFF", "MANUAL", "AUTO"} else "MANUAL"
        self.dry_run = _truthy(settings.get("soar_dry_run", os.getenv("SOAR_DRY_RUN", "true")))
        self.auto_min_score = int(settings.get("soar_auto_min_score", os.getenv("SOAR_AUTO_MIN_SCORE", "90")))
        self.allow_private = _truthy(settings.get(
            "soar_allow_private_ip_blocking", os.getenv("SOAR_ALLOW_PRIVATE_IP_BLOCKING", "false")
        ))
        raw_allowlist = settings.get("soar_allowlist", os.getenv("SOAR_ALLOWLIST", ""))
        self.allowlist = self._parse_allowlist(raw_allowlist) | DEFAULT_ALLOWLIST
        self.self_ips = set(self_ips) if self_ips is not None else analyzer_ip_addresses()

    @staticmethod
    def _parse_allowlist(raw):
        if isinstance(raw, (list, tuple, set)):
            values = raw
        else:
            try:
                values = json.loads(raw) if raw else []
            except (TypeError, json.JSONDecodeError):
                values = str(raw or "").split(",")
        return {str(item).strip() for item in values if str(item).strip()}

    def validate_ip(self, value):
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return False, None, "invalid or empty IP address"
        canonical = str(address)
        if address.is_loopback or address.is_unspecified:
            return False, canonical, "loopback or unspecified address"
        if address.is_multicast or address.is_reserved or canonical == "255.255.255.255":
            return False, canonical, "multicast, broadcast, or reserved address"
        if canonical in self.allowlist:
            return False, canonical, "address is allowlisted"
        if canonical in self.self_ips:
            return False, canonical, "address belongs to the Analyzer"
        if address.is_private and not self.allow_private:
            return False, canonical, "private address blocking is disabled"
        return True, canonical, "approved"

    def auto_qualifies(self, incident):
        severity = str(incident.get("severity") or incident.get("threat_level") or "").upper()
        try:
            score = int(incident.get("threat_score") or incident.get("risk_score") or 0)
        except (TypeError, ValueError):
            score = 0
        threat = str(incident.get("threat_type") or incident.get("attack_type") or "").lower()
        # Correlated brute force is an allowed automatic condition, but only
        # when the correlation explicitly confirms it (not one failed login).
        correlated_brute_force = "possible brute force attack" in threat
        return severity == "CRITICAL" or score >= self.auto_min_score or correlated_brute_force
