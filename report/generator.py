from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agent.models import Finding, ReportMetadata, ScanResult, Severity, SEVERITY_WEIGHTS
from analyzers.attack_mapper import ATTACKMapper

_NIST_FAMILY_NAMES: dict[str, str] = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "PT": "PII Processing and Transparency",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}

_NIST_CONTROL_DESCRIPTIONS: dict[str, str] = {
    "AC-2": "Account Management",
    "AC-3": "Access Enforcement",
    "AC-4": "Information Flow Enforcement",
    "AC-6": "Least Privilege",
    "AC-7": "Unsuccessful Login Attempts",
    "AC-12": "Session Termination",
    "AC-14": "Permitted Actions Without Identification",
    "AU-2": "Event Logging",
    "AU-3": "Content of Audit Records",
    "AU-9": "Protection of Audit Information",
    "AU-12": "Audit Record Generation",
    "CM-2": "Baseline Configuration",
    "CM-3": "Configuration Change Control",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "CM-14": "Signed Components",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-3": "Device Identification and Authentication",
    "IA-5": "Authenticator Management",
    "IA-8": "Identification and Authentication (Non-Organizational Users)",
    "SA-3": "System Development Life Cycle",
    "SA-8": "Security and Privacy Engineering Principles",
    "SA-15": "Development Process, Standards, and Tools",
    "SC-5": "Denial of Service Protection",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-17": "Public Key Infrastructure Certificates",
    "SC-23": "Session Authenticity",
    "SC-28": "Protection of Information at Rest",
    "SI-2": "Flaw Remediation",
    "SI-3": "Malicious Code Protection",
    "SI-4": "System Monitoring",
    "SI-7": "Software, Firmware, and Information Integrity",
    "SI-10": "Information Input Validation",
}


class ReportGenerator:
    def __init__(self) -> None:
        templates_dir = Path(__file__).parent / "templates"
        self._env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape([]),  # markdown, not HTML
        )
        self._env.filters["truncate"] = self._truncate

        data_dir = Path(__file__).parent.parent / "data"
        with open(data_dir / "owasp_categories.json", encoding="utf-8") as f:
            self._owasp_data: dict = json.load(f)

        self._attack_mapper = ATTACKMapper()

    def generate(
        self,
        scan_result: ScanResult,
        executive_summary: str,
        meta: ReportMetadata,
    ) -> str:
        findings = sorted(
            scan_result.findings,
            key=lambda f: SEVERITY_WEIGHTS.get(f.severity, 0),
            reverse=True,
        )

        def by_severity(sev: Severity) -> list[Finding]:
            return [f for f in findings if f.severity == sev]

        context = {
            "repo_name": scan_result.repo_name,
            "repo_url": scan_result.repo_url,
            "branch": scan_result.branch,
            "scanned_at": scan_result.scanned_at.strftime("%Y-%m-%d %H:%M UTC"),
            "detected_languages": scan_result.detected_languages,
            "total_findings": len(findings),
            "risk_score": meta.risk_score,
            "executive_summary": executive_summary,
            "meta": meta,
            "findings": findings,
            "critical_findings": by_severity(Severity.CRITICAL),
            "high_findings": by_severity(Severity.HIGH),
            "medium_findings": by_severity(Severity.MEDIUM),
            "low_findings": by_severity(Severity.LOW),
            "cve_findings": [f for f in findings if f.cve_ids],
            "owasp_summary": self._build_owasp_summary(findings),
            "nist_mapping": self._build_nist_mapping(findings),
            "attack_summary": self._attack_mapper.build_summary(findings),
            "scanner_counts": self._build_scanner_counts(findings),
            "scanner_errors": scan_result.scanner_errors,
        }

        template = self._env.get_template("report_template.md")
        return template.render(**context)

    def _build_owasp_summary(self, findings: list[Finding]) -> dict:
        summary: dict[str, dict] = {}
        for finding in findings:
            for cat in finding.owasp_categories:
                if cat not in summary:
                    cat_data = self._owasp_data.get(cat, {})
                    summary[cat] = {
                        "count": 0,
                        "max_severity": Severity.INFO,
                        "findings": [],
                        "description": cat_data.get("description", ""),
                    }
                entry = summary[cat]
                entry["count"] += 1
                if SEVERITY_WEIGHTS.get(finding.severity, 0) > SEVERITY_WEIGHTS.get(entry["max_severity"], 0):
                    entry["max_severity"] = finding.severity
                if len(entry["findings"]) < 10:
                    entry["findings"].append(finding.title)
        # Sort by max severity descending
        return dict(
            sorted(
                summary.items(),
                key=lambda x: SEVERITY_WEIGHTS.get(x[1]["max_severity"], 0),
                reverse=True,
            )
        )

    def _build_nist_mapping(self, findings: list[Finding]) -> dict:
        control_findings: dict[str, int] = defaultdict(int)
        for finding in findings:
            for ctrl in finding.nist_controls:
                control_findings[ctrl] += 1

        result = {}
        for ctrl, count in sorted(control_findings.items()):
            family_prefix = ctrl.split("-")[0]
            result[ctrl] = {
                "family": _NIST_FAMILY_NAMES.get(family_prefix, family_prefix),
                "description": _NIST_CONTROL_DESCRIPTIONS.get(ctrl, ""),
                "count": count,
            }
        return result

    def _build_scanner_counts(self, findings: list[Finding]) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for f in findings:
            counts[f.source] += 1
        return dict(counts)

    @staticmethod
    def _truncate(value: str, length: int = 80) -> str:
        if len(value) <= length:
            return value
        return value[: length - 3] + "..."
