from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from agent.models import Finding


class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(
        self,
        findings: list[Finding],
        repo_metadata: dict[str, Any],
    ) -> tuple[list[Finding], str]:
        """Enrich findings with remediation advice and return an executive summary."""
        ...
