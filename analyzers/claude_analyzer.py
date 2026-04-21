from __future__ import annotations

import json
import textwrap
from typing import Any

import anthropic

from agent.config import Config
from agent.models import Finding, Severity

_SYSTEM_PROMPT = textwrap.dedent("""
    You are a senior application security engineer and penetration tester with deep expertise in:
    - NIST 800-53 Rev5 security controls and compliance mapping
    - OWASP Top 10 2021 vulnerability categories
    - MITRE CVE database and exploit assessment
    - Static code analysis and secure coding practices
    - Risk-based vulnerability prioritization

    Your role is to analyze security findings from automated scanners, validate their severity,
    provide practical remediation guidance, and synthesize findings into clear executive summaries.

    NIST 800-53 Rev5 Control Families Reference:
    - AC: Access Control — user permissions, least privilege, separation of duties
    - AU: Audit and Accountability — logging, monitoring, event records
    - CA: Assessment, Authorization, and Monitoring — security assessments, authorization
    - CM: Configuration Management — baseline configs, change control, software inventory
    - IA: Identification and Authentication — credential management, MFA, session control
    - IR: Incident Response — detection, reporting, handling procedures
    - SA: System and Services Acquisition — secure development, supply chain risk
    - SC: System and Communications Protection — network protection, cryptography, transmission
    - SI: System and Information Integrity — malware protection, input validation, error handling

    OWASP Top 10 2021:
    A01: Broken Access Control | A02: Cryptographic Failures | A03: Injection
    A04: Insecure Design | A05: Security Misconfiguration | A06: Vulnerable/Outdated Components
    A07: Auth Failures | A08: Software & Data Integrity | A09: Logging & Monitoring Failures
    A10: SSRF

    When analyzing findings:
    1. Focus on actionable, specific remediation steps
    2. Consider false-positive likelihood for automated scanner findings
    3. Prioritize based on exploitability and business impact
    4. Be concise — developers will read these recommendations
""").strip()


class ClaudeAnalyzer:
    def __init__(self, api_key: str | None = None) -> None:
        self._client = anthropic.Anthropic(api_key=api_key or Config.ANTHROPIC_API_KEY)
        self._model = Config.CLAUDE_MODEL

    def analyze(
        self,
        findings: list[Finding],
        repo_metadata: dict[str, Any],
    ) -> tuple[list[Finding], str]:
        if not findings:
            return findings, "No vulnerabilities were detected in this scan."

        enriched = self._enrich_findings(findings, repo_metadata)
        summary = self._generate_executive_summary(enriched, repo_metadata)
        return enriched, summary

    # ── Finding enrichment ────────────────────────────────────────────────────

    def _enrich_findings(
        self, findings: list[Finding], repo_metadata: dict[str, Any]
    ) -> list[Finding]:
        chunk_size = Config.MAX_FINDINGS_PER_BATCH
        for i in range(0, len(findings), chunk_size):
            chunk = findings[i : i + chunk_size]
            self._enrich_chunk(chunk, repo_metadata)
        return findings

    def _enrich_chunk(
        self, chunk: list[Finding], repo_metadata: dict[str, Any]
    ) -> None:
        findings_data = [
            {
                "id": f.id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "source": f.source,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "cwe_ids": f.cwe_ids,
                "cve_ids": f.cve_ids,
                "owasp_categories": f.owasp_categories,
                "nist_controls": f.nist_controls,
            }
            for f in chunk
        ]

        user_content = (
            f"Repository: {repo_metadata.get('name', 'unknown')}\n"
            f"Languages: {', '.join(repo_metadata.get('languages', []))}\n\n"
            "For each finding below, provide:\n"
            "1. A concise remediation recommendation (2-3 sentences max)\n"
            "2. Whether this is likely a true positive or possible false positive\n\n"
            "Respond with a JSON array where each element has:\n"
            '{"id": "<finding_id>", "remediation": "<steps>", "false_positive_risk": "low|medium|high"}\n\n'
            f"Findings:\n{json.dumps(findings_data, indent=2)}"
        )

        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=[
                    {
                        "type": "text",
                        "text": _SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": user_content}],
            )
            raw = response.content[0].text
            # Extract JSON array from response
            start = raw.find("[")
            end = raw.rfind("]") + 1
            if start >= 0 and end > start:
                enrichments = json.loads(raw[start:end])
                id_map = {e["id"]: e for e in enrichments if "id" in e}
                for finding in chunk:
                    if finding.id in id_map:
                        enrich = id_map[finding.id]
                        finding.remediation = enrich.get("remediation", "")
        except Exception:
            # Non-fatal — leave remediation as None if Claude call fails
            pass

    # ── Executive summary ─────────────────────────────────────────────────────

    def _generate_executive_summary(
        self, findings: list[Finding], repo_metadata: dict[str, Any]
    ) -> str:
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        top_findings = sorted(
            findings,
            key=lambda f: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(f.severity, 0),
            reverse=True,
        )[:10]

        top_data = [
            {
                "title": f.title,
                "severity": f.severity,
                "owasp": f.owasp_categories[:2],
                "nist": f.nist_controls[:3],
                "file": f.file_path,
                "cve_ids": f.cve_ids,
            }
            for f in top_findings
        ]

        user_content = (
            f"Repository: {repo_metadata.get('name', 'unknown')}\n"
            f"Description: {repo_metadata.get('description', 'N/A')}\n"
            f"Languages: {', '.join(repo_metadata.get('languages', []))}\n\n"
            f"Vulnerability counts: {json.dumps({k: v for k, v in severity_counts.items()})}\n"
            f"Total findings: {len(findings)}\n\n"
            f"Top findings:\n{json.dumps(top_data, indent=2)}\n\n"
            "Write a 200-300 word executive summary covering:\n"
            "1. Overall security posture and risk level\n"
            "2. Most critical vulnerability categories found\n"
            "3. NIST 800-53 control families with gaps\n"
            "4. Top 3 immediate remediation priorities\n"
            "5. Compliance implications (NIST/OWASP)\n\n"
            "Write for a technical manager audience. Be direct and specific."
        )

        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=1024,
                system=[
                    {
                        "type": "text",
                        "text": _SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": user_content}],
            )
            return response.content[0].text
        except Exception as e:
            total = len(findings)
            critical = severity_counts.get(Severity.CRITICAL, 0)
            high = severity_counts.get(Severity.HIGH, 0)
            return (
                f"Security scan completed. Found {total} total vulnerabilities "
                f"({critical} critical, {high} high severity). "
                f"Manual review of findings recommended. (Executive summary generation failed: {e})"
            )
