#!/usr/bin/env python3
"""Cybersecurity Agent — scan a GitHub repository for vulnerabilities."""
from __future__ import annotations

import sys

import click
from rich.console import Console

from agent.config import Config
from agent.orchestrator import Orchestrator

console = Console()


@click.command()
@click.argument("repo_url")
@click.option("--branch", default="main", show_default=True, help="Branch to scan")
@click.option(
    "--provider",
    type=click.Choice(["anthropic", "openai"], case_sensitive=False),
    default=None,
    help="AI provider for analysis (overrides AI_PROVIDER env var)",
)
@click.option(
    "--report-path",
    default="SECURITY_REPORT.md",
    show_default=True,
    help="Path for the report file inside the repository",
)
@click.option(
    "--output-dir",
    default="./reports",
    show_default=True,
    help="Local directory to save the report",
)
@click.option(
    "--inject/--no-inject",
    default=True,
    help="Commit the report to the GitHub repository",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False),
    default="high",
    show_default=True,
    help="Exit code 1 if findings at this severity or above are found",
)
def scan(
    repo_url: str,
    branch: str,
    provider: str | None,
    report_path: str,
    output_dir: str,
    inject: bool,
    severity_threshold: str,
) -> None:
    """Scan a GitHub repository for security vulnerabilities.

    REPO_URL is the full URL of the GitHub repository to scan,
    e.g. https://github.com/owner/repo
    """
    console.print(
        "\n[bold]Cybersecurity Agent[/bold] — "
        "NIST 800-53 Rev5 · OWASP Top 10 2025 · MITRE CVE · MITRE ATT&CK\n"
    )

    active_provider = (provider or Config.AI_PROVIDER).lower()

    # Validate config
    errors = Config.validate(provider=active_provider)
    if errors:
        for err in errors:
            console.print(f"[red]✗ Config error:[/red] {err}")
        if active_provider == "anthropic" and not Config.ANTHROPIC_API_KEY:
            console.print(
                "[yellow]Hint:[/yellow] Set ANTHROPIC_API_KEY in your .env file, "
                "or use --provider openai with OPENAI_API_KEY."
            )
        elif active_provider == "openai" and not Config.OPENAI_API_KEY:
            console.print(
                "[yellow]Hint:[/yellow] Set OPENAI_API_KEY in your .env file, "
                "or use --provider anthropic with ANTHROPIC_API_KEY."
            )
        if not Config.GITHUB_TOKEN and inject:
            console.print(
                "[yellow]Hint:[/yellow] Set GITHUB_TOKEN to enable report injection, "
                "or use --no-inject to skip."
            )
        sys.exit(2)

    console.print(f"  [dim]AI provider:[/dim] {active_provider}")

    try:
        orchestrator = Orchestrator(provider=active_provider)
        result = orchestrator.run(
            repo_url=repo_url,
            branch=branch,
            inject=inject,
            report_path=report_path,
            output_dir=output_dir,
            severity_threshold=severity_threshold,
        )

        threshold_weight = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0,
        }[severity_threshold.lower()]

        has_threshold_findings = any(
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(f.severity, 0)
            >= threshold_weight
            for f in result.findings
        )

        sys.exit(1 if has_threshold_findings else 0)

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]✗ Fatal error:[/red] {e}")
        raise


if __name__ == "__main__":
    scan()
