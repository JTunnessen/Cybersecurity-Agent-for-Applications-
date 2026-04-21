# Cybersecurity Agent for Applications

A CLI-driven security scanning agent that analyzes GitHub repositories for vulnerabilities across multiple security frameworks and commits a comprehensive report directly back to the repository.

## What It Does

1. **Clones** the target GitHub repository (shallow clone for speed)
2. **Scans** the code using four complementary methods:
   - **Static Analysis** — Semgrep (multi-language) and Bandit (Python-specific)
   - **Dependency Audit** — Safety for Python packages
   - **CVE Scanning** — OSV.dev batch API for all ecosystem dependency manifests
3. **Maps** every finding to:
   - **NIST 800-53 Rev5** control families (AC, AU, CM, IA, SC, SI, ...)
   - **OWASP Top 10 2021** categories (A01–A10)
   - **MITRE CVE IDs** from the NVD database
4. **Analyzes** findings with Claude AI to generate remediation advice and an executive summary
5. **Commits** a `SECURITY_REPORT.md` file to the repository with a prioritized TODO checklist

## Supported Languages

| Language | Static Analysis | Dependency Scanning |
|----------|----------------|---------------------|
| Python | Bandit + Semgrep | Safety + OSV.dev |
| JavaScript | Semgrep | OSV.dev (npm) |
| TypeScript | Semgrep | OSV.dev (npm) |
| PHP | Semgrep | OSV.dev (Packagist) |

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

Install Semgrep separately (recommended — it's large):

```bash
pip install semgrep
# or
brew install semgrep
```

### 2. Configure environment

Copy the example and fill in your keys:

```bash
cp .env.example .env
```

```env
ANTHROPIC_API_KEY=sk-ant-...      # Required: get from console.anthropic.com
GITHUB_TOKEN=ghp_...              # Required: needs repo read + write access
NVD_API_KEY=                      # Optional: increases NVD rate limit to 50 req/30s
WORK_DIR=/tmp/cyb-agent-scans     # Optional: where repos are cloned
```

**GitHub token permissions required:**
- `repo` (read repository contents + commit files)

### 3. Run a scan

```bash
# Scan and commit report to the repository
python main.py https://github.com/owner/repo

# Scan without committing (dry run)
python main.py https://github.com/owner/repo --no-inject

# Scan a specific branch
python main.py https://github.com/owner/repo --branch develop

# Change the report file path in the repository
python main.py https://github.com/owner/repo --report-path docs/SECURITY.md

# Save report locally to a custom directory
python main.py https://github.com/owner/repo --output-dir /tmp/my-reports
```

## CLI Reference

```
Usage: python main.py [OPTIONS] REPO_URL

  Scan a GitHub repository for security vulnerabilities.

Options:
  --branch TEXT                   Branch to scan  [default: main]
  --report-path TEXT              Path for report inside repository  [default: SECURITY_REPORT.md]
  --output-dir TEXT               Local directory to save the report  [default: ./reports]
  --inject / --no-inject          Commit the report to GitHub  [default: inject]
  --severity-threshold [critical|high|medium|low|info]
                                  Exit code 1 if findings at this level found  [default: high]
  --help                          Show this message and exit.
```

**Exit codes:**
- `0` — Scan complete, no findings at or above severity threshold
- `1` — Findings at or above the severity threshold were found
- `2` — Configuration error (missing API keys)

## Report Structure

The generated `SECURITY_REPORT.md` contains:

| Section | Description |
|---------|-------------|
| Risk Dashboard | Severity counts and overall risk score (0–10) |
| Executive Summary | AI-generated risk narrative with top priorities |
| Vulnerability Findings | Full table with file, line, OWASP category, NIST controls, CVEs |
| OWASP Top 10 Analysis | Findings grouped by OWASP 2021 category |
| NIST 800-53 Control Mapping | Controls failing and the findings that triggered them |
| CVE References | Table of known CVEs in dependencies |
| Remediation Checklist | Prioritized `- [ ]` tasks grouped by severity |
| Appendix | Scanner runtime details |

## Using as a CI/CD Gate

Add to your GitHub Actions workflow to block PRs with high/critical findings:

```yaml
- name: Security scan
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    pip install -r requirements.txt semgrep
    python main.py ${{ github.server_url }}/${{ github.repository }} \
      --branch ${{ github.ref_name }} \
      --severity-threshold high \
      --no-inject
```

## Architecture

```
main.py (CLI)
  └─ agent/orchestrator.py          ← Pipeline coordinator
       ├─ github_integration/
       │   ├─ repo_fetcher.py        ← Shallow git clone
       │   └─ report_injector.py    ← GitHub API commit
       ├─ scanners/
       │   ├─ bandit_scanner.py     ← Python SAST
       │   ├─ semgrep_scanner.py    ← Multi-language SAST
       │   ├─ safety_scanner.py     ← Python dep audit
       │   └─ cve_scanner.py        ← OSV.dev CVE lookup
       ├─ analyzers/
       │   ├─ owasp_mapper.py       ← CWE → OWASP category
       │   ├─ nist_mapper.py        ← CWE/OWASP → NIST controls
       │   └─ claude_analyzer.py    ← AI enrichment (Anthropic SDK)
       └─ report/
           └─ generator.py          ← Jinja2 markdown report
```

## Security Frameworks Covered

### NIST 800-53 Rev5
Maps findings to control families: AC (Access Control), AU (Audit), CM (Configuration Management), IA (Identification & Authentication), SC (System & Communications Protection), SI (System & Information Integrity), SA (System & Services Acquisition).

### OWASP Top 10 2021
Categorizes findings across all 10 categories: Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security Misconfiguration, Vulnerable Components, Auth Failures, Software Integrity, Logging Failures, and SSRF.

### MITRE CVE
Queries the [OSV.dev](https://osv.dev) batch API to match dependency versions against known CVEs across PyPI, npm, Packagist, RubyGems, Go, Cargo, and Maven ecosystems.

### Static Code Analysis
- **Bandit**: Python-specific security linting (SQL injection, shell injection, hardcoded secrets, insecure crypto, pickle deserialization, and 60+ more checks)
- **Semgrep**: Pattern-based analysis using `p/owasp-top-ten`, `p/secrets`, and language-specific security rulesets

## License

MIT
