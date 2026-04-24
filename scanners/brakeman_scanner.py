from __future__ import annotations

import json

from agent.models import Finding, Severity
from scanners.base import BaseScanner

# Brakeman warning_type → CWE
_BRAKEMAN_CWE: dict[str, str] = {
    "SQL Injection": "CWE-89",
    "Cross-Site Scripting": "CWE-79",
    "Remote Code Execution": "CWE-94",
    "Command Injection": "CWE-78",
    "Dangerous Eval": "CWE-78",
    "File Access": "CWE-22",
    "Dynamic Render Path": "CWE-22",
    "Path Traversal": "CWE-22",
    "Mass Assignment": "CWE-915",
    "Nested Attributes": "CWE-915",
    "Unscoped Find": "CWE-639",
    "Redirect": "CWE-601",
    "Session Setting": "CWE-384",
    "Cross-Site Request Forgery": "CWE-352",
    "Deserialize": "CWE-502",
    "XML Injection": "CWE-611",
    "Format Validation": "CWE-20",
    "Header Injection": "CWE-113",
    "Regex Denial of Service": "CWE-1333",
    "Denial of Service": "CWE-400",
    "Weak Hash": "CWE-327",
    "Weak Cryptography": "CWE-327",
    "SSL Verification Bypass": "CWE-295",
    "Authentication": "CWE-287",
    "Authorization": "CWE-285",
    "Verification Skipped": "CWE-297",
    "Information Disclosure": "CWE-200",
    "Sensitive Data Exposure": "CWE-200",
    "Template Injection": "CWE-94",
    "Illegal Instruction": "CWE-94",
}

_CONFIDENCE_SEVERITY: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Weak": Severity.LOW,
}


class BrakemanScanner(BaseScanner):
    def scan(self, repo_path: str) -> list[Finding]:
        cmd = [
            "brakeman",
            "--no-progress",
            "--no-summary",
            "--format", "json",
            "--quiet",
            repo_path,
        ]
        stdout, stderr, rc = self.run_subprocess(cmd, repo_path)

        # Brakeman exits 3 when warnings found — that's expected
        if not stdout:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        findings = []
        for warning in data.get("warnings", []):
            warning_type = warning.get("warning_type", "Unknown")
            cwe = _BRAKEMAN_CWE.get(warning_type)
            cwe_ids = [cwe] if cwe else []

            confidence = warning.get("confidence", "Weak")
            severity = _CONFIDENCE_SEVERITY.get(confidence, Severity.LOW)

            finding = Finding(
                source="brakeman",
                title=f"{warning_type}: {warning.get('check_name', '')}".strip(": "),
                description=warning.get("message", ""),
                severity=severity,
                file_path=warning.get("file", ""),
                line_number=warning.get("line"),
                cwe_ids=cwe_ids,
                references=[warning.get("link", "")] if warning.get("link") else [],
            )
            findings.append(finding)

        return findings
