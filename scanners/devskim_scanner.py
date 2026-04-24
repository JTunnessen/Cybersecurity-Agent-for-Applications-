from __future__ import annotations

import json

from agent.models import Finding, Severity
from scanners.base import BaseScanner

# DevSkim rule ID prefix → CWE (covers the most common security rules)
_DEVSKIM_RULE_CWE: dict[str, str] = {
    "DS137138": "CWE-327",   # Weak Hash - MD5
    "DS126858": "CWE-327",   # Weak Hash - SHA-1
    "DS130138": "CWE-327",   # Weak Cipher (DES, RC2, RC4)
    "DS168931": "CWE-330",   # Weak RNG (Math.Random, rand())
    "DS196098": "CWE-89",    # SQL Injection
    "DS176209": "CWE-798",   # Hardcoded Password / Secret
    "DS112835": "CWE-798",   # Hardcoded API Key
    "DS190020": "CWE-321",   # Hardcoded Encryption Key
    "DS181500": "CWE-78",    # Command / Process Injection
    "DS154189": "CWE-601",   # Open Redirect
    "DS109706": "CWE-601",   # Unvalidated Redirect
    "DS102855": "CWE-611",   # XML External Entity (XXE)
    "DS144436": "CWE-79",    # Cross-Site Scripting (XSS)
    "DS440000": "CWE-22",    # Path Traversal
    "DS162092": "CWE-90",    # LDAP Injection
    "DS173237": "CWE-1333",  # Regex Denial of Service (ReDoS)
    "DS185832": "CWE-502",   # Insecure Deserialization
    "DS122150": "CWE-326",   # SSL/TLS Weak Protocol Version
    "DS101338": "CWE-352",   # Cross-Site Request Forgery (CSRF)
    "DS134711": "CWE-94",    # Server-side Template Injection
    "DS125134": "CWE-200",   # Hardcoded IP Address
    "DS104456": "CWE-489",   # Debug / Development Features Enabled
    "DS117516": "CWE-614",   # Cookie Without Secure Flag
    "DS163877": "CWE-295",   # SSL Certificate Validation Disabled
}

# DevSkim rule severity (from rule properties) → Finding Severity
_DEVSKIM_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "important": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "bestpractice": Severity.LOW,
    "manualreview": Severity.INFO,
}

# SARIF level fallback when rule-level severity is unavailable
_SARIF_LEVEL: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


class DevSkimScanner(BaseScanner):
    def scan(self, repo_path: str) -> list[Finding]:
        cmd = [
            "devskim",
            "analyze",
            "-I", repo_path,
            "-f", "sarif",
        ]
        stdout, stderr, rc = self.run_subprocess(cmd, repo_path)

        if not stdout:
            return []

        try:
            sarif = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        runs = sarif.get("runs", [])
        if not runs:
            return []

        run = runs[0]
        rule_meta = self._extract_rule_metadata(run)
        return self._parse_results(run.get("results", []), rule_meta, repo_path)

    def _extract_rule_metadata(self, run: dict) -> dict[str, dict]:
        """Build ruleId → {severity, description, cwe} from the SARIF driver rules."""
        meta: dict[str, dict] = {}
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        for rule in rules:
            rule_id = rule.get("id", "")
            props = rule.get("properties", {})
            severity_str = props.get("severity", "").lower()
            description = (
                rule.get("shortDescription", {}).get("text", "")
                or rule.get("fullDescription", {}).get("text", "")
            )
            cwe = _DEVSKIM_RULE_CWE.get(rule_id)
            meta[rule_id] = {
                "severity": _DEVSKIM_SEVERITY.get(severity_str),
                "description": description,
                "cwe": cwe,
            }
        return meta

    def _parse_results(
        self, results: list[dict], rule_meta: dict[str, dict], repo_path: str
    ) -> list[Finding]:
        findings = []
        for result in results:
            rule_id = result.get("ruleId", "")
            meta = rule_meta.get(rule_id, {})

            sarif_level = result.get("level", "warning").lower()
            severity = meta.get("severity") or _SARIF_LEVEL.get(sarif_level, Severity.MEDIUM)

            message = result.get("message", {}).get("text", "")
            description = meta.get("description") or message

            cwe = meta.get("cwe") or _DEVSKIM_RULE_CWE.get(rule_id)
            cwe_ids = [cwe] if cwe else []

            file_path = ""
            line_number = None
            locations = result.get("locations", [])
            if locations:
                phys = locations[0].get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                # Strip file:/// scheme and make relative to repo_path
                if uri.startswith("file:///"):
                    uri = uri[8:]
                file_path = uri
                region = phys.get("region", {})
                line_number = region.get("startLine")

            findings.append(Finding(
                source="devskim",
                title=f"DevSkim: {rule_id}" if not meta.get("description") else meta["description"],
                description=description,
                severity=severity,
                file_path=file_path,
                line_number=line_number,
                cwe_ids=cwe_ids,
            ))

        return findings
