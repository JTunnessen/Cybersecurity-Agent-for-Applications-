from __future__ import annotations

import json
from pathlib import Path

from agent.config import Config
from agent.models import Finding


class OWASPMapper:
    def __init__(self) -> None:
        path = Config.DATA_DIR / "cwe_to_owasp.json"
        with open(path, encoding="utf-8") as f:
            self._cwe_map: dict[str, str] = json.load(f)

    def map_finding(self, finding: Finding) -> list[str]:
        categories: list[str] = list(finding.owasp_categories)
        seen = set(categories)
        for cwe in finding.cwe_ids:
            cat = self._cwe_map.get(cwe.upper())
            if cat and cat not in seen:
                categories.append(cat)
                seen.add(cat)
        return categories

    def map_all(self, findings: list[Finding]) -> None:
        for finding in findings:
            finding.owasp_categories = self.map_finding(finding)
