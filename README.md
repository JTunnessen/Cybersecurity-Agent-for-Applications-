# Cybersecurity Agent for Applications

A CLI-driven security scanning agent that analyzes GitHub repositories for vulnerabilities across six security frameworks and commits a comprehensive report directly back to the repository.

## What It Does

1. **Clones** the target GitHub repository (shallow clone for speed)
2. **Scans** the code using four complementary methods:
   - **Static Analysis** — Semgrep (multi-language) and Bandit (Python-specific)
   - **Dependency Audit** — Safety for Python packages
   - **CVE Scanning** — OSV.dev batch API for all ecosystem dependency manifests
   - **CISA KEV Check** — Cross-references all CVEs against the CISA Known Exploited Vulnerabilities catalog
3. **Maps** every finding to six security frameworks:
   - **NIST 800-53 Rev5** control families (AC, AU, CM, IA, SC, SI, SR, ...)
   - **OWASP Top 10 2025** categories (A01–A10)
   - **MITRE CVE IDs** from the NVD / OSV.dev database
   - **MITRE ATT&CK Enterprise** tactics and techniques (T1190, T1552, T1195, ...)
   - **CISA KEV Catalog** — flags actively exploited CVEs with CISA-mandated remediation deadlines and days remaining
4. **Analyzes** findings with your choice of AI — Claude (Anthropic) or GPT-4o (OpenAI) — to generate per-finding remediation advice and an executive summary that covers OWASP 2025, NIST gaps, ATT&CK threat context, and KEV urgency
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

```bash
cp .env.example .env
```

```env
AI_PROVIDER=anthropic             # "anthropic" or "openai" (default: anthropic)
ANTHROPIC_API_KEY=sk-ant-...      # Required if AI_PROVIDER=anthropic
OPENAI_API_KEY=sk-...             # Required if AI_PROVIDER=openai
GITHUB_TOKEN=ghp_...              # Required: needs repo read + write access
NVD_API_KEY=                      # Optional: increases NVD rate limit to 50 req/30s
WORK_DIR=/tmp/cyb-agent-scans     # Optional: where repos are cloned
```

**GitHub token permissions required:** `repo` (read contents + commit files)

### 3. Run a scan

```bash
# Scan and commit report (uses AI_PROVIDER from .env, defaults to anthropic)
python main.py https://github.com/owner/repo

# Explicitly use Claude (Anthropic)
python main.py https://github.com/owner/repo --provider anthropic

# Use GPT-4o (OpenAI) instead
python main.py https://github.com/owner/repo --provider openai

# Scan without committing (dry run)
python main.py https://github.com/owner/repo --no-inject

# Scan a specific branch
python main.py https://github.com/owner/repo --branch develop

# Custom report path in the repository
python main.py https://github.com/owner/repo --report-path docs/SECURITY.md

# Save report locally to a custom directory
python main.py https://github.com/owner/repo --output-dir /tmp/my-reports
```

## CLI Reference

```
Usage: python main.py [OPTIONS] REPO_URL

  Scan a GitHub repository for security vulnerabilities.

Options:
  --branch TEXT                      Branch to scan  [default: main]
  --provider [anthropic|openai]      AI provider for analysis (overrides AI_PROVIDER env var)
  --report-path TEXT                 Path for report inside repository  [default: SECURITY_REPORT.md]
  --output-dir TEXT                  Local directory to save the report  [default: ./reports]
  --inject / --no-inject             Commit the report to GitHub  [default: inject]
  --severity-threshold [critical|high|medium|low|info]
                                     Exit code 1 if findings at this level found  [default: high]
  --help                             Show this message and exit.
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
| Executive Summary | AI-generated risk narrative covering OWASP 2025, ATT&CK threats, NIST gaps, and top priorities |
| Vulnerability Findings | Full table with file, line, OWASP 2025 category, NIST controls, ATT&CK techniques, CVEs |
| OWASP Top 10 2025 Analysis | Findings grouped by OWASP 2025 category with descriptions |
| MITRE ATT&CK Coverage | Technique table linked to attack.mitre.org; per-technique finding breakdown |
| NIST 800-53 Control Gap Analysis | Controls failing and the findings that triggered them |
| CVE / Dependency References | Table of known CVEs in dependencies |
| CISA KEV Analysis | Actively exploited CVEs with due dates, days remaining, and required actions (BOD 22-01) |
| Remediation Checklist | KEV items listed first with deadlines, then prioritized `- [ ]` tasks with ATT&CK IDs, CVEs, and NIST controls |
| Appendix | Scanner runtime details and warnings |

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
  └─ agent/orchestrator.py             ← Pipeline coordinator (ThreadPoolExecutor)
       ├─ github_integration/
       │   ├─ repo_fetcher.py           ← Shallow git clone + repo metadata
       │   └─ report_injector.py       ← GitHub API commit (create or update file)
       ├─ scanners/
       │   ├─ bandit_scanner.py        ← Python SAST (60+ CWE mappings)
       │   ├─ semgrep_scanner.py       ← Multi-language SAST (language-detected rulesets)
       │   ├─ safety_scanner.py        ← Python dependency audit
       │   └─ cve_scanner.py           ← OSV.dev batch CVE lookup
       ├─ analyzers/
       │   ├─ owasp_mapper.py          ← CWE → OWASP Top 10 2025 category
       │   ├─ nist_mapper.py           ← CWE/OWASP → NIST 800-53 Rev5 controls
       │   ├─ attack_mapper.py         ← CWE/OWASP → MITRE ATT&CK techniques
       │   ├─ base_analyzer.py         ← Abstract BaseAnalyzer interface
       │   ├─ claude_analyzer.py       ← Anthropic Claude implementation (prompt caching)
       │   └─ openai_analyzer.py       ← OpenAI GPT-4o implementation
       ├─ data/
       │   ├─ cwe_to_owasp.json        ← 100+ CWE → OWASP 2025 lookup table
       │   ├─ nist_controls.json       ← CWE/OWASP → NIST control IDs
       │   ├─ attack_mappings.json     ← CWE/OWASP → ATT&CK technique IDs + metadata
       │   └─ owasp_categories.json    ← OWASP 2025 category descriptions
       └─ report/
           ├─ generator.py             ← Jinja2 markdown report builder
           └─ templates/
               └─ report_template.md  ← Report template with all framework sections
```

## Security Frameworks Covered

### NIST 800-53 Rev5
Maps findings to control families: AC (Access Control), AU (Audit and Accountability), CM (Configuration Management), IA (Identification & Authentication), SA (System & Services Acquisition), SC (System & Communications Protection), SI (System & Information Integrity), SR (Supply Chain Risk Management).

### OWASP Top 10 2025

| ID | Category | Notable Change from 2021 |
|----|----------|--------------------------|
| A01 | Broken Access Control | Absorbs SSRF (was A10:2021) |
| A02 | Security Misconfiguration | Rises from #5 (IaC/cloud misconfig) |
| A03 | Software Supply Chain Failures | **NEW** — expanded from Vulnerable Components |
| A04 | Cryptographic Failures | Drops from #2 |
| A05 | Injection | Drops from #3 |
| A06 | Identification and Authentication Failures | Was #7 |
| A07 | Software and Data Integrity Failures | Was #8 |
| A08 | Security Logging and Alerting Failures | Renamed to emphasize alerting |
| A09 | Insecure Design | Drops from #4 |
| A10 | Mishandling of Exceptional Conditions | **NEW** — error handling, resource exhaustion |

### MITRE ATT&CK Enterprise
Maps findings to adversary techniques across Initial Access, Execution, Credential Access, Privilege Escalation, and Impact tactics. Key techniques covered:

| Technique | Name | Common CWEs |
|-----------|------|-------------|
| T1190 | Exploit Public-Facing Application | SQL injection, XSS, XXE, SSRF, RCE |
| T1059 | Command and Scripting Interpreter | OS command injection, eval, deserialization |
| T1552 | Unsecured Credentials | Hardcoded secrets, credentials in files |
| T1195 | Supply Chain Compromise | Vulnerable/malicious dependencies |
| T1557 | Adversary-in-the-Middle | Weak TLS, missing cert validation |
| T1078 | Valid Accounts | Auth bypass, session fixation |
| T1499 | Endpoint Denial of Service | Resource exhaustion, infinite loops |
| T1539 | Steal Web Session Cookie | XSS, insecure session handling |

### MITRE CVE
Queries the [OSV.dev](https://osv.dev) batch API to match dependency versions against known CVEs across PyPI, npm, Packagist, RubyGems, Go, Cargo, and Maven ecosystems.

### CISA Known Exploited Vulnerabilities (KEV)

Cross-references all detected CVEs against the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — a curated list of vulnerabilities with confirmed active exploitation in the wild.

**KEV findings receive special treatment:**
- Automatically elevated to at least **HIGH** severity (active exploitation trumps CVSS score)
- Dedicated report section showing CISA-mandated remediation timeline
- Remediation checklist flags KEV items first with due date and days remaining
- AI analysis explicitly calls out CISA BOD 22-01 mandate urgency

| KEV Field | Description |
|-----------|-------------|
| Date Added | When CISA added this CVE to the catalog |
| **Due Date** | CISA-mandated remediation deadline (BOD 22-01) |
| Days Remaining | Countdown to deadline (negative = overdue) |
| Required Action | CISA-prescribed remediation action |
| Vendor / Product | Affected product from the advisory |

### Static Code Analysis
- **Bandit**: Python-specific security linting — SQL injection, shell injection, hardcoded credentials, insecure crypto, pickle deserialization, and 60+ additional checks with CWE mappings
- **Semgrep**: Pattern-based analysis using `p/owasp-top-ten`, `p/secrets`, and language-specific security rulesets (`p/python`, `p/javascript`, `p/typescript`, `p/php`)

## License

MIT
