from __future__ import annotations

import json
import os
from collections import Counter

from agent.models import Finding, Severity
from scanners.base import BaseScanner

_EXT_TO_LANGUAGE: dict[str, str] = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "React",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "React",
    ".php": "PHP",
    ".php3": "PHP",
    ".php4": "PHP",
    ".php5": "PHP",
    ".phtml": "PHP",
    ".rb": "Ruby",
    ".rake": "Ruby",
    ".gemspec": "Ruby",
    ".cs": "C#",
    ".fs": "F#",
    ".fsx": "F#",
    ".fsi": "F#",
    ".vb": "VB.NET",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".sass": "CSS",
    ".less": "CSS",
}

_LANGUAGE_RULESETS: dict[str, list[str]] = {
    "Python": ["p/python", "p/bandit"],
    "JavaScript": ["p/javascript"],
    "TypeScript": ["p/typescript"],
    "React": ["p/javascript", "p/react"],
    "PHP": ["p/php"],
    "Ruby": ["p/ruby"],
    "C#": ["p/csharp"],
}

_ALWAYS_RULESETS = ["p/owasp-top-ten", "p/secrets"]

_SEMGREP_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def detect_languages(repo_path: str) -> list[str]:
    ext_counts: Counter = Counter()
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            lang = _EXT_TO_LANGUAGE.get(ext)
            if lang:
                ext_counts[lang] += 1
    total = sum(ext_counts.values()) or 1
    return [lang for lang, count in ext_counts.items() if count / total >= 0.03 or count >= 3]


class SemgrepScanner(BaseScanner):
    def scan(self, repo_path: str, languages: list[str] | None = None) -> list[Finding]:
        if languages is None:
            languages = detect_languages(repo_path)

        rulesets = list(_ALWAYS_RULESETS)
        for lang in languages:
            rulesets.extend(_LANGUAGE_RULESETS.get(lang, []))
        rulesets = list(dict.fromkeys(rulesets))  # deduplicate, preserve order

        all_findings: dict[str, Finding] = {}

        for ruleset in rulesets:
            cmd = [
                "semgrep",
                "--config", ruleset,
                "--json",
                "--no-git-ignore",
                "--quiet",
                repo_path,
            ]
            stdout, stderr, rc = self.run_subprocess(cmd, repo_path)
            if not stdout:
                continue
            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                continue

            for result in data.get("results", []):
                finding = self._parse_result(result)
                key = finding.dedup_key()
                if key not in all_findings:
                    all_findings[key] = finding
                else:
                    existing = all_findings[key]
                    existing.cwe_ids = list(dict.fromkeys(existing.cwe_ids + finding.cwe_ids))
                    existing.owasp_categories = list(
                        dict.fromkeys(existing.owasp_categories + finding.owasp_categories)
                    )

        return list(all_findings.values())

    def _parse_result(self, result: dict) -> Finding:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        # Extract CWE IDs
        cwe_raw = metadata.get("cwe", [])
        if isinstance(cwe_raw, str):
            cwe_raw = [cwe_raw]
        cwe_ids = [self._normalize_cwe(c) for c in cwe_raw if c]

        # Extract OWASP categories from metadata
        owasp_raw = metadata.get("owasp", [])
        if isinstance(owasp_raw, str):
            owasp_raw = [owasp_raw]
        owasp_categories = [o for o in owasp_raw if o]

        severity_str = extra.get("severity", "WARNING").upper()
        severity = _SEMGREP_SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        # Bump severity based on confidence
        confidence = metadata.get("confidence", "").upper()
        if confidence == "HIGH" and severity == Severity.MEDIUM:
            severity = Severity.HIGH

        start = result.get("start", {})

        return Finding(
            source="semgrep",
            title=result.get("check_id", "semgrep-finding"),
            description=extra.get("message", ""),
            severity=severity,
            file_path=result.get("path", ""),
            line_number=start.get("line"),
            cwe_ids=cwe_ids,
            owasp_categories=owasp_categories,
            references=metadata.get("references", []),
        )

    @staticmethod
    def _normalize_cwe(raw: str) -> str:
        raw = raw.strip()
        if raw.upper().startswith("CWE-"):
            return raw.upper()
        if raw.isdigit():
            return f"CWE-{raw}"
        # Handle formats like "CWE-79: XSS"
        if ":" in raw:
            return raw.split(":")[0].strip().upper()
        return raw.upper()
