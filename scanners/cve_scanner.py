from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import requests
from packaging.version import Version, InvalidVersion

from agent.config import Config
from agent.models import Finding, Severity
from scanners.base import BaseScanner

_MANIFEST_PARSERS = {
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "requirements-test.txt": "pypi",
    "dev-requirements.txt": "pypi",
    "package.json": "npm",
    "composer.json": "packagist",
    "Gemfile.lock": "rubygems",
    "go.sum": "go",
    "Cargo.lock": "crates.io",
    "pom.xml": "maven",
}

_CVSS_TO_SEVERITY: list[tuple[float, Severity]] = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
]

# Cached KEV catalog: cveID → full KEV entry dict
_kev_cache: dict[str, dict] | None = None


def _cvss_to_severity(score: float) -> Severity:
    for threshold, severity in _CVSS_TO_SEVERITY:
        if score >= threshold:
            return severity
    return Severity.INFO


def _fetch_kev_catalog() -> dict[str, dict]:
    """Return {cveID: full_kev_entry} from the CISA Known Exploited Vulnerabilities catalog."""
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache
    try:
        resp = requests.get(Config.CISA_KEV_URL, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        _kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    except Exception:
        _kev_cache = {}
    return _kev_cache


class CVEScanner(BaseScanner):
    def scan(self, repo_path: str) -> list[Finding]:
        packages = self._extract_all_packages(repo_path)
        if not packages:
            return []

        osv_vulns = self._query_osv_batch(packages)
        kev_catalog = _fetch_kev_catalog()
        return self._build_findings(osv_vulns, kev_catalog)

    # ── Package extraction ────────────────────────────────────────────────────

    def _extract_all_packages(self, repo_path: str) -> list[dict]:
        packages = []
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d != "node_modules"]
            for fname in files:
                ecosystem = _MANIFEST_PARSERS.get(fname)
                if not ecosystem:
                    continue
                fpath = os.path.join(root, fname)
                try:
                    pkgs = self._parse_manifest(fpath, ecosystem)
                    packages.extend(pkgs)
                except Exception:
                    pass
        return packages

    def _parse_manifest(self, fpath: str, ecosystem: str) -> list[dict]:
        with open(fpath, encoding="utf-8", errors="ignore") as f:
            content = f.read()

        if ecosystem == "pypi":
            return self._parse_requirements(content, ecosystem)
        if ecosystem == "npm":
            return self._parse_package_json(content, ecosystem)
        if ecosystem == "packagist":
            return self._parse_composer_json(content, ecosystem)
        if ecosystem == "rubygems":
            return self._parse_gemfile_lock(content, ecosystem)
        if ecosystem == "go":
            return self._parse_go_sum(content, ecosystem)
        if ecosystem == "crates.io":
            return self._parse_cargo_lock(content, ecosystem)
        return []

    def _parse_requirements(self, content: str, ecosystem: str) -> list[dict]:
        pkgs = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Match "package==version" or "package>=version"
            m = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([^\s,;]+)", line)
            if m:
                pkgs.append({"name": m.group(1), "version": m.group(2), "ecosystem": ecosystem})
        return pkgs

    def _parse_package_json(self, content: str, ecosystem: str) -> list[dict]:
        pkgs = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return pkgs
        for section in ("dependencies", "devDependencies"):
            for name, ver in data.get(section, {}).items():
                # Strip semver operators: ^1.2.3 → 1.2.3
                clean = re.sub(r"^[\^~>=<]", "", ver).strip()
                if clean:
                    pkgs.append({"name": name, "version": clean, "ecosystem": ecosystem})
        return pkgs

    def _parse_composer_json(self, content: str, ecosystem: str) -> list[dict]:
        pkgs = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return pkgs
        for section in ("require", "require-dev"):
            for name, ver in data.get(section, {}).items():
                if name == "php":
                    continue
                clean = re.sub(r"[^0-9.]", "", ver)
                if clean:
                    pkgs.append({"name": name, "version": clean, "ecosystem": ecosystem})
        return pkgs

    def _parse_gemfile_lock(self, content: str, ecosystem: str) -> list[dict]:
        pkgs = []
        in_specs = False
        for line in content.splitlines():
            if "  specs:" in line:
                in_specs = True
                continue
            if in_specs:
                if line.startswith("    ") and not line.startswith("      "):
                    m = re.match(r"\s+([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", line)
                    if m:
                        pkgs.append({"name": m.group(1), "version": m.group(2), "ecosystem": ecosystem})
                elif line.strip() == "":
                    in_specs = False
        return pkgs

    def _parse_go_sum(self, content: str, ecosystem: str) -> list[dict]:
        pkgs = []
        for line in content.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                ver = parts[1].lstrip("v").split("/")[0]
                pkgs.append({"name": name, "version": ver, "ecosystem": ecosystem})
        return pkgs

    def _parse_cargo_lock(self, content: str, ecosystem: str) -> list[dict]:
        pkgs = []
        current: dict = {}
        for line in content.splitlines():
            line = line.strip()
            if line == "[[package]]":
                if current.get("name") and current.get("version"):
                    pkgs.append({**current, "ecosystem": ecosystem})
                current = {}
            elif line.startswith("name = "):
                current["name"] = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = "):
                current["version"] = line.split("=", 1)[1].strip().strip('"')
        if current.get("name") and current.get("version"):
            pkgs.append({**current, "ecosystem": ecosystem})
        return pkgs

    # ── OSV.dev API ────────────────────────────────────────────────────────────

    def _query_osv_batch(self, packages: list[dict]) -> list[dict]:
        results = []
        # Chunk into batches of 100
        for i in range(0, len(packages), 100):
            chunk = packages[i:i + 100]
            queries = []
            for pkg in chunk:
                queries.append({
                    "package": {
                        "name": pkg["name"],
                        "ecosystem": self._osv_ecosystem(pkg["ecosystem"]),
                    },
                    "version": pkg["version"],
                })
            try:
                resp = requests.post(
                    Config.OSV_BATCH_URL,
                    json={"queries": queries},
                    timeout=30,
                )
                resp.raise_for_status()
                data = resp.json()
                for pkg, batch_result in zip(chunk, data.get("results", [])):
                    for vuln in batch_result.get("vulns", []):
                        vuln["_pkg"] = pkg
                        results.append(vuln)
            except Exception:
                pass
            time.sleep(0.1)
        return results

    @staticmethod
    def _osv_ecosystem(ecosystem: str) -> str:
        mapping = {
            "pypi": "PyPI",
            "npm": "npm",
            "packagist": "Packagist",
            "rubygems": "RubyGems",
            "go": "Go",
            "crates.io": "crates.io",
            "maven": "Maven",
        }
        return mapping.get(ecosystem, ecosystem)

    # ── Finding construction ────────────────────────────────────────────────────

    def _build_findings(self, osv_vulns: list[dict], kev_catalog: dict[str, dict]) -> list[Finding]:
        findings = []
        for vuln in osv_vulns:
            pkg = vuln.get("_pkg", {})
            aliases = vuln.get("aliases", [])
            cve_ids = [a for a in aliases if a.startswith("CVE-")]

            # Get CVSS score from severity field
            cvss_score = self._extract_cvss(vuln)
            severity = _cvss_to_severity(cvss_score) if cvss_score else Severity.MEDIUM

            # Check KEV catalog for any matching CVE
            kev_entry = next((kev_catalog[cve] for cve in cve_ids if cve in kev_catalog), None)

            # KEV findings are always at least HIGH — actively exploited in the wild
            if kev_entry:
                severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
                if severity_order.index(severity) < severity_order.index(Severity.HIGH):
                    severity = Severity.HIGH

            summary = vuln.get("summary", "Known vulnerability in dependency")
            details = vuln.get("details", "")
            description = f"{summary}. {details}".strip(". ")

            references = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

            finding = Finding(
                source="cve",
                title=f"Vulnerable package: {pkg.get('name', 'unknown')} ({vuln.get('id', '')})",
                description=description,
                severity=severity,
                package_name=pkg.get("name"),
                package_version=pkg.get("version"),
                cve_ids=cve_ids,
                cwe_ids=["CWE-1035"],  # Using Component with Known Vulnerabilities
                references=references[:5],
            )

            # Populate full KEV metadata if this CVE is in the catalog
            if kev_entry:
                finding.is_kev = True
                finding.kev_date_added = kev_entry.get("dateAdded")
                finding.kev_due_date = kev_entry.get("dueDate")
                finding.kev_required_action = kev_entry.get("requiredAction")
                finding.kev_vendor_project = kev_entry.get("vendorProject")
                finding.kev_product = kev_entry.get("product")
                finding.kev_short_description = kev_entry.get("shortDescription")

            findings.append(finding)

        return findings

    @staticmethod
    def _extract_cvss(vuln: dict) -> float | None:
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                score_str = sev.get("score", "")
                # CVSS vector: extract base score from AV:N/AC:L/... or numeric
                m = re.search(r"(\d+\.\d+)$", score_str)
                if m:
                    try:
                        return float(m.group(1))
                    except ValueError:
                        pass
        return None
