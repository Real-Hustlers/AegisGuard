"""Windows enterprise deployment contract and static preflight checks."""

from __future__ import annotations

import re
from pathlib import Path


REQUIRED_DEPLOYMENT_FILES = (
    "app.spec",
    "backend/analyzer/AegisGuardAnalyzerMTLS.spec",
    "backend/collector/AegisGuardCollector.spec",
    "backend/collector/config_loader.py",
    "backend/analyzer/mtls_server.py",
    "install_collector.ps1",
    "deploy/windows/configure_collector_mtls.ps1",
    "deploy/windows/install_analyzer_mtls.ps1",
    "deploy/windows/run_analyzer_mtls.ps1",
    "BUILD-README.txt",
)


DEPLOYMENT_TEXT_FILES = (
    "BUILD-README.txt",
    "app.spec",
    "backend/collector/AegisGuardCollector.spec",
    "install_collector.ps1",
    "deploy/windows/configure_collector_mtls.ps1",
    "deploy/windows/install_analyzer_mtls.ps1",
    "deploy/windows/run_analyzer_mtls.ps1",
)


PACKAGING_SPEC_FILES = (
    "app.spec",
    "backend/analyzer/AegisGuardAnalyzerMTLS.spec",
    "backend/collector/AegisGuardCollector.spec",
)


FORBIDDEN_BUNDLE_BASENAMES = {
    "config.json",
    "aegisguard.db",
    "collector_state.db",
}


FORBIDDEN_BUNDLE_SUFFIXES = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".key",
    ".pem",
    ".pfx",
    ".p12",
    ".crt",
    ".cer",
}


_STRING_LITERAL_RE = re.compile(
    r"""(?P<quote>["'])(?P<value>.*?)(?P=quote)"""
)


_DEVELOPER_PATH_PATTERNS = (
    re.compile(
        r"""(?i)\b[A-Z]:\\Users\\[^\\/:*?"<>|\r\n]+"""
    ),
    re.compile(
        r"""(?i)(?<![A-Za-z0-9_])/home/[^/\s]+"""
    ),
    re.compile(
        r"""(?i)(?<![A-Za-z0-9_])/Users/[^/\s]+"""
    ),
)


def deployment_layout():
    """Return the supported Windows installation separation."""

    return {
        "analyzer": {
            "binary": (
                r"%ProgramFiles%\AegisGuard\Analyzer"
                r"\AegisGuardAnalyzer.exe"
            ),
            "data_directory": (
                r"%ProgramData%\AegisGuard\Analyzer"
            ),
            "database": (
                r"%ProgramData%\AegisGuard\Analyzer"
                r"\aegisguard.db"
            ),
            "ml_registry": (
                r"%ProgramData%\AegisGuard\Analyzer"
                r"\ml_registry"
            ),
            "tls_directory": (
                r"%ProgramData%\AegisGuard\Analyzer\tls"
            ),
        },
        "collector": {
            "binary": (
                r"%ProgramFiles%\AegisGuard\Collector"
                r"\AegisGuardCollector.exe"
            ),
            "data_directory": (
                r"%ProgramData%\AegisGuard\Collector"
            ),
            "config": (
                r"%ProgramData%\AegisGuard\Collector"
                r"\config.json"
            ),
            "state": (
                r"%ProgramData%\AegisGuard\Collector"
                r"\collector_state.db"
            ),
            "tls_directory": (
                r"%ProgramData%\AegisGuard\Collector\tls"
            ),
        },
    }


def find_developer_paths_in_text(text):
    """Find user-specific absolute development paths."""

    source = str(text or "")
    findings = []

    for pattern in _DEVELOPER_PATH_PATTERNS:
        for match in pattern.finditer(source):
            findings.append(
                match.group(0)
            )

    return findings


def _string_literals(text):
    return [
        match.group("value")
        for match in _STRING_LITERAL_RE.finditer(
            str(text or "")
        )
    ]


def find_forbidden_packaging_literals(text):
    """Find runtime state or secret material named in packaging specs."""

    findings = []

    for literal in _string_literals(text):
        normalized = literal.replace(
            "\\",
            "/",
        )

        name = normalized.rsplit(
            "/",
            1,
        )[-1].lower()

        suffix = Path(name).suffix.lower()

        if (
            name in FORBIDDEN_BUNDLE_BASENAMES
            or suffix in FORBIDDEN_BUNDLE_SUFFIXES
        ):
            findings.append({
                "literal": literal,
                "reason": (
                    "runtime_or_sensitive_material"
                ),
            })

    return findings


def validate_repository(root):
    """Validate S10 deployment source hygiene without executing installers."""

    root = Path(root).resolve()
    issues = []

    for relative in REQUIRED_DEPLOYMENT_FILES:
        path = root / relative

        if not path.is_file():
            issues.append({
                "check": "required_file",
                "path": relative,
                "message": (
                    "required deployment source is missing"
                ),
            })

    for relative in DEPLOYMENT_TEXT_FILES:
        path = root / relative

        if not path.is_file():
            continue

        source = path.read_text(
            encoding="utf-8-sig"
        )

        for finding in (
            find_developer_paths_in_text(
                source
            )
        ):
            issues.append({
                "check": "developer_path",
                "path": relative,
                "message": finding,
            })

    for relative in PACKAGING_SPEC_FILES:
        path = root / relative

        if not path.is_file():
            continue

        source = path.read_text(
            encoding="utf-8-sig"
        )

        for finding in (
            find_forbidden_packaging_literals(
                source
            )
        ):
            issues.append({
                "check": "packaging_material",
                "path": relative,
                "message": finding["literal"],
            })

    return {
        "ok": not issues,
        "root": str(root),
        "required_file_count": len(
            REQUIRED_DEPLOYMENT_FILES
        ),
        "issues": issues,
        "layout": deployment_layout(),
    }
