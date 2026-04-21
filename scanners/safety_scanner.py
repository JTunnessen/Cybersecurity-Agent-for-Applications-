from __future__ import annotations

import json
import os

from agent.models import Finding, Severity
from scanners.base import BaseScanner

_REQ_FILENAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements_dev.txt",
    "requirements-test.txt",
    "dev-requirements.txt",
    "test-requirements.txt",
}


class SafetyScanner(BaseScanner):
    def scan(self, repo_path: str) -> list[Finding]:
        req_files = self._find_requirement_files(repo_path)
        if not req_files:
            return []

        findings = []
        for req_file in req_files:
            findings.extend(self._scan_file(req_file, repo_path))
        return findings

    def _find_requirement_files(self, repo_path: str) -> list[str]:
        found = []
        for root, _, files in os.walk(repo_path):
            # Skip hidden dirs and common non-source dirs
            if any(part.startswith(".") or part in ("node_modules", ".git")
                   for part in root.split(os.sep)):
                continue
            for fname in files:
                if fname in _REQ_FILENAMES:
                    found.append(os.path.join(root, fname))
        return found

    def _scan_file(self, req_file: str, repo_path: str) -> list[Finding]:
        cmd = ["safety", "check", "-r", req_file, "--json", "--output", "json"]
        stdout, stderr, rc = self.run_subprocess(cmd, repo_path)

        if not stdout:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        # Safety JSON format varies by version; handle both list and dict output
        vulnerabilities = []
        if isinstance(data, list):
            vulnerabilities = data
        elif isinstance(data, dict):
            vulnerabilities = data.get("vulnerabilities", [])

        findings = []
        for vuln in vulnerabilities:
            # Safety outputs: [vuln_id, package, installed, affected, advisory, CVE]
            if isinstance(vuln, list) and len(vuln) >= 5:
                pkg_name = vuln[1] if len(vuln) > 1 else "unknown"
                installed = vuln[2] if len(vuln) > 2 else ""
                advisory = vuln[4] if len(vuln) > 4 else ""
                cve_id = vuln[5] if len(vuln) > 5 else ""
                cve_ids = [cve_id] if cve_id else []
            elif isinstance(vuln, dict):
                pkg_name = vuln.get("package_name", "unknown")
                installed = vuln.get("analyzed_version", "")
                advisory = vuln.get("advisory", "")
                cve_ids = [c for c in [vuln.get("CVE")] if c]
            else:
                continue

            finding = Finding(
                source="safety",
                title=f"Vulnerable dependency: {pkg_name}",
                description=advisory,
                severity=Severity.HIGH,
                package_name=pkg_name,
                package_version=installed,
                cve_ids=cve_ids,
                cwe_ids=["CWE-1035"],  # Using Component with Known Vulnerabilities
            )
            findings.append(finding)

        return findings
