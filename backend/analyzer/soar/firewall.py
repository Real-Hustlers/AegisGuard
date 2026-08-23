"""Windows Defender Firewall adapter restricted to AegisGuard-owned rules."""

import hashlib
import subprocess
import sys


RULE_PREFIX = "AegisGuard-SOAR-Block-"


def rule_name_for_ip(ip):
    return RULE_PREFIX + hashlib.sha256(ip.encode("ascii")).hexdigest()[:16]


class FirewallError(RuntimeError):
    pass


class WindowsFirewall:
    """Minimal adapter; no arbitrary PowerShell is accepted from callers."""

    def __init__(self, runner=subprocess.run, platform=None):
        self.runner = runner
        self.platform = platform or sys.platform

    def _run(self, command):
        if not self.platform.startswith("win"):
            raise FirewallError("Windows Firewall response is available only on the Analyzer Windows host")
        try:
            result = self.runner(command, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError(str(exc)) from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "firewall command failed").strip()
            raise FirewallError(detail)
        return result

    def _probe(self, command):
        """Run the exact-rule existence probe, where exit 1 means absent."""
        if not self.platform.startswith("win"):
            raise FirewallError("Windows Firewall response is available only on the Analyzer Windows host")
        try:
            result = self.runner(command, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise FirewallError(str(exc)) from exc
        if result.returncode not in (0, 1):
            raise FirewallError((result.stderr or result.stdout or "firewall rule check failed").strip())
        return result.returncode == 0

    @staticmethod
    def _powershell(script):
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]

    def block_ip(self, ip):
        name = rule_name_for_ip(ip)
        # ip is parsed and canonicalized by ResponsePolicy before reaching this
        # adapter; name is a fixed prefix plus a SHA-256 hex digest.
        exists = "if (Get-NetFirewallRule -DisplayName '" + name + "' -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }"
        if self._probe(self._powershell(exists)):
            return "ALREADY_EXISTS", name
        create = (
            "New-NetFirewallRule -DisplayName '" + name + "' -Group 'AegisGuard SOAR' "
            "-Direction Inbound -Action Block -RemoteAddress '" + ip + "' -Profile Any | Out-Null"
        )
        self._run(self._powershell(create))
        return "EXECUTED", name

    def unblock_ip(self, ip):
        name = rule_name_for_ip(ip)
        # Exact, deterministic rule name: never use a wildcard or remove
        # firewall rules that AegisGuard did not create.
        remove = "Remove-NetFirewallRule -DisplayName '" + name + "' -ErrorAction SilentlyContinue"
        self._run(self._powershell(remove))
        return "ROLLED_BACK", name
