from __future__ import annotations

import json

from agent.config import Config
from agent.models import Finding


class ATTACKMapper:
    def __init__(self) -> None:
        path = Config.DATA_DIR / "attack_mappings.json"
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)

        # Separate the technique metadata from the mappings
        self._techniques: dict[str, dict] = raw.pop("_techniques", {})
        # Remove comment key
        self._mappings: dict[str, list[str]] = {
            k: v for k, v in raw.items() if not k.startswith("_")
        }

    def map_finding(self, finding: Finding) -> list[str]:
        techniques: list[str] = list(finding.attack_techniques)
        seen = set(techniques)

        for cwe in finding.cwe_ids:
            for tid in self._mappings.get(cwe.upper(), []):
                if tid not in seen:
                    techniques.append(tid)
                    seen.add(tid)

        for owasp in finding.owasp_categories:
            for tid in self._mappings.get(owasp, []):
                if tid not in seen:
                    techniques.append(tid)
                    seen.add(tid)

        return techniques

    def map_all(self, findings: list[Finding]) -> None:
        for finding in findings:
            finding.attack_techniques = self.map_finding(finding)

    def get_technique_info(self, technique_id: str) -> dict:
        return self._techniques.get(technique_id, {
            "name": technique_id,
            "tactic": "Unknown",
            "tactic_id": "",
            "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
        })

    def build_summary(self, findings: list[Finding]) -> dict:
        """Build {technique_id: {name, tactic, url, count, max_severity, findings}} dict."""
        from collections import defaultdict
        from agent.models import SEVERITY_WEIGHTS

        summary: dict[str, dict] = {}
        for finding in findings:
            for tid in finding.attack_techniques:
                if tid not in summary:
                    info = self.get_technique_info(tid)
                    summary[tid] = {
                        "name": info.get("name", tid),
                        "tactic": info.get("tactic", "Unknown"),
                        "url": info.get("url", ""),
                        "count": 0,
                        "max_severity": "INFO",
                        "findings": [],
                    }
                entry = summary[tid]
                entry["count"] += 1
                if SEVERITY_WEIGHTS.get(finding.severity, 0) > SEVERITY_WEIGHTS.get(entry["max_severity"], 0):
                    entry["max_severity"] = finding.severity
                if len(entry["findings"]) < 5:
                    entry["findings"].append(finding.title)

        return dict(
            sorted(
                summary.items(),
                key=lambda x: SEVERITY_WEIGHTS.get(x[1]["max_severity"], 0),
                reverse=True,
            )
        )
