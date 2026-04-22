from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from agent.config import Config
from agent.models import Finding, ReportMetadata, ScanResult, Severity, SEVERITY_WEIGHTS
from analyzers.attack_mapper import ATTACKMapper
from analyzers.claude_analyzer import ClaudeAnalyzer
from analyzers.nist_mapper import NISTMapper
from analyzers.owasp_mapper import OWASPMapper
from github_integration.repo_fetcher import RepoFetcher
from github_integration.report_injector import ReportInjector
from report.generator import ReportGenerator
from scanners.bandit_scanner import BanditScanner
from scanners.cve_scanner import CVEScanner
from scanners.safety_scanner import SafetyScanner
from scanners.semgrep_scanner import SemgrepScanner, detect_languages

console = Console()


class Orchestrator:
    def __init__(self) -> None:
        self._repo_fetcher = RepoFetcher()
        self._report_injector = ReportInjector()
        self._owasp_mapper = OWASPMapper()
        self._nist_mapper = NISTMapper()
        self._attack_mapper = ATTACKMapper()
        self._claude_analyzer = ClaudeAnalyzer()
        self._report_generator = ReportGenerator()

    def run(
        self,
        repo_url: str,
        branch: str = "main",
        inject: bool = True,
        report_path: str = "SECURITY_REPORT.md",
        output_dir: str = "./reports",
        severity_threshold: str = "low",
    ) -> ScanResult:
        local_path: str | None = None

        try:
            # ── Step 1: Clone repository ──────────────────────────────────────
            console.print(f"\n[bold blue]▶ Cloning repository:[/bold blue] {repo_url} (branch: {branch})")
            local_path = self._repo_fetcher.clone_repo(repo_url, branch)
            repo_metadata = self._repo_fetcher.get_repo_metadata(repo_url)
            console.print(f"  [green]✓[/green] Cloned to {local_path}")

            # ── Step 2: Detect languages ──────────────────────────────────────
            languages = detect_languages(local_path)
            console.print(f"  [dim]Detected languages: {', '.join(languages) or 'none'}[/dim]")

            scan_result = ScanResult(
                repo_url=repo_url,
                repo_name=repo_metadata.get("name", "unknown"),
                branch=branch,
                detected_languages=languages,
            )

            # ── Step 3: Run scanners in parallel ──────────────────────────────
            console.print("\n[bold blue]▶ Running security scanners...[/bold blue]")
            all_findings = self._run_scanners_parallel(local_path, languages, scan_result)
            console.print(f"  [green]✓[/green] {len(all_findings)} raw findings collected")

            # ── Step 4: Deduplicate findings ──────────────────────────────────
            findings = self._deduplicate(all_findings)
            console.print(f"  [green]✓[/green] {len(findings)} unique findings after deduplication")
            scan_result.findings = findings

            # ── Step 5: Map OWASP, NIST, and ATT&CK ──────────────────────────
            console.print("\n[bold blue]▶ Mapping to OWASP 2025, NIST 800-53 Rev5, and MITRE ATT&CK...[/bold blue]")
            self._owasp_mapper.map_all(findings)
            self._nist_mapper.map_all(findings)
            self._attack_mapper.map_all(findings)
            console.print("  [green]✓[/green] Framework mappings complete")

            # ── Step 6: Claude analysis ───────────────────────────────────────
            console.print("\n[bold blue]▶ Analyzing findings with Claude AI...[/bold blue]")
            findings, executive_summary = self._claude_analyzer.analyze(findings, repo_metadata)
            console.print("  [green]✓[/green] AI analysis complete")

            # ── Step 7: Generate report ───────────────────────────────────────
            console.print("\n[bold blue]▶ Generating security report...[/bold blue]")
            meta = ReportMetadata.from_findings(findings)
            meta.executive_summary = executive_summary
            report_markdown = self._report_generator.generate(scan_result, executive_summary, meta)

            # Save report locally
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            local_report = Path(output_dir) / report_path
            local_report.write_text(report_markdown, encoding="utf-8")
            console.print(f"  [green]✓[/green] Report saved locally: {local_report}")

            # ── Step 8: Inject into GitHub ────────────────────────────────────
            if inject:
                console.print("\n[bold blue]▶ Injecting report into repository...[/bold blue]")
                try:
                    report_url = self._report_injector.inject(
                        repo_url=repo_url,
                        report_path=report_path,
                        content=report_markdown,
                        branch=branch,
                    )
                    console.print(f"  [green]✓[/green] Report committed: {report_url}")
                except Exception as e:
                    scan_result.scanner_errors.append(f"GitHub injection failed: {e}")
                    console.print(f"  [yellow]⚠[/yellow] GitHub injection failed: {e}")

            # ── Summary ───────────────────────────────────────────────────────
            console.print("\n[bold green]━━━ Scan Complete ━━━[/bold green]")
            console.print(f"  Total findings: {len(findings)}")
            console.print(f"  Critical: {meta.total_critical} | High: {meta.total_high} | "
                          f"Medium: {meta.total_medium} | Low: {meta.total_low}")
            console.print(f"  Risk score: {meta.risk_score}/10")

            return scan_result

        finally:
            if local_path:
                self._repo_fetcher.cleanup(local_path)

    # ── Scanner orchestration ─────────────────────────────────────────────────

    def _run_scanners_parallel(
        self, repo_path: str, languages: list[str], scan_result: ScanResult
    ) -> list[Finding]:
        tasks = {}

        def add_task(name: str, fn):
            tasks[name] = fn

        add_task("semgrep", lambda: SemgrepScanner().scan(repo_path, languages))

        if "Python" in languages:
            add_task("bandit", lambda: BanditScanner().scan(repo_path))
            add_task("safety", lambda: SafetyScanner().scan(repo_path))

        add_task("cve", lambda: CVEScanner().scan(repo_path))

        all_findings: list[Finding] = []

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(fn): name for name, fn in tasks.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results = future.result()
                    console.print(f"  [dim]{name}:[/dim] {len(results)} findings")
                    all_findings.extend(results)
                except Exception as e:
                    msg = f"{name} scanner failed: {e}"
                    scan_result.scanner_errors.append(msg)
                    console.print(f"  [yellow]⚠[/yellow] {msg}")

        return all_findings

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for f in findings:
            key = f.dedup_key()
            if key not in seen:
                seen[key] = f
            else:
                existing = seen[key]
                # Keep the finding with more metadata
                existing.cwe_ids = list(dict.fromkeys(existing.cwe_ids + f.cwe_ids))
                existing.cve_ids = list(dict.fromkeys(existing.cve_ids + f.cve_ids))
                existing.references = list(dict.fromkeys(existing.references + f.references))
                # Prefer higher severity
                if SEVERITY_WEIGHTS.get(f.severity, 0) > SEVERITY_WEIGHTS.get(existing.severity, 0):
                    existing.severity = f.severity
        return list(seen.values())
