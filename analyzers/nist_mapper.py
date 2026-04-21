from __future__ import annotations

import json

from agent.config import Config
from agent.models import Finding


class NISTMapper:
    def __init__(self) -> None:
        path = Config.DATA_DIR / "nist_controls.json"
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
        # Remove the comment key
        self._controls: dict[str, list[str]] = {
            k: v for k, v in raw.items() if not k.startswith("_")
        }

    def map_finding(self, finding: Finding) -> list[str]:
        controls: set[str] = set()
        for cwe in finding.cwe_ids:
            controls.update(self._controls.get(cwe.upper(), []))
        for owasp in finding.owasp_categories:
            controls.update(self._controls.get(owasp, []))
        return sorted(controls)

    def map_all(self, findings: list[Finding]) -> None:
        for finding in findings:
            finding.nist_controls = self.map_finding(finding)
