from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_WEIGHTS: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str  # "bandit" | "semgrep" | "safety" | "cve"
    title: str
    description: str
    severity: Severity
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cwe_ids: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    owasp_categories: list[str] = Field(default_factory=list)
    nist_controls: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    is_kev: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    kev_required_action: Optional[str] = None
    kev_vendor_project: Optional[str] = None
    kev_product: Optional[str] = None
    kev_short_description: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = Field(default_factory=list)

    def dedup_key(self) -> str:
        primary_cwe = self.cwe_ids[0] if self.cwe_ids else self.title
        return f"{self.file_path}:{self.line_number}:{primary_cwe}"


class ScanResult(BaseModel):
    repo_url: str
    repo_name: str
    branch: str
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    detected_languages: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    dependency_files: list[str] = Field(default_factory=list)
    scanner_errors: list[str] = Field(default_factory=list)


class ReportMetadata(BaseModel):
    executive_summary: str = ""
    total_critical: int = 0
    total_high: int = 0
    total_medium: int = 0
    total_low: int = 0
    total_info: int = 0
    risk_score: float = 0.0
    top_remediation_priorities: list[str] = Field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "ReportMetadata":
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1
        total = len(findings)
        max_score = total * SEVERITY_WEIGHTS["CRITICAL"] if total > 0 else 1
        weighted = sum(SEVERITY_WEIGHTS[f.severity] * 1 for f in findings)
        risk = round((weighted / max_score) * 10, 1) if max_score > 0 else 0.0
        return cls(
            total_critical=counts[Severity.CRITICAL],
            total_high=counts[Severity.HIGH],
            total_medium=counts[Severity.MEDIUM],
            total_low=counts[Severity.LOW],
            total_info=counts[Severity.INFO],
            risk_score=min(risk, 10.0),
        )
