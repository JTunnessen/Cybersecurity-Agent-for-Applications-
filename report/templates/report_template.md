# Security Assessment Report: {{ repo_name }}

| Field | Value |
|-------|-------|
| **Repository** | `{{ repo_url }}` |
| **Branch** | `{{ branch }}` |
| **Scan Date** | {{ scanned_at }} |
| **Scanner** | Cybersecurity Agent v1.0 |
| **Languages Detected** | {{ detected_languages | join(', ') or 'N/A' }} |
| **Total Findings** | {{ total_findings }} |
| **Overall Risk Score** | **{{ risk_score }}/10** |

---

## Executive Summary

{{ executive_summary }}

---

## Risk Dashboard

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 CRITICAL | {{ meta.total_critical }} | {% if meta.total_critical > 0 %}Immediate action required{% else %}None found{% endif %} |
| 🟠 HIGH | {{ meta.total_high }} | {% if meta.total_high > 0 %}Action required{% else %}None found{% endif %} |
| 🟡 MEDIUM | {{ meta.total_medium }} | {% if meta.total_medium > 0 %}Plan remediation{% else %}None found{% endif %} |
| 🔵 LOW | {{ meta.total_low }} | {% if meta.total_low > 0 %}Address when possible{% else %}None found{% endif %} |
| ⚪ INFO | {{ meta.total_info }} | Informational |

---

## Vulnerability Findings

{% if findings %}
| ID | Title | Severity | File | Line | OWASP 2025 | NIST Controls | ATT&CK | CVEs |
|----|-------|----------|------|------|------------|---------------|--------|------|
{% for f in findings %}| `{{ f.id[:8] }}` | {{ f.title | truncate(55) }} | **{{ f.severity }}** | {% if f.file_path %}`{{ f.file_path | truncate(35) }}`{% else %}N/A{% endif %} | {{ f.line_number or 'N/A' }} | {{ f.owasp_categories[0] if f.owasp_categories else 'N/A' }} | {{ f.nist_controls[:3] | join(', ') or 'N/A' }} | {{ f.attack_techniques[:2] | join(', ') or 'N/A' }} | {{ f.cve_ids[:2] | join(', ') or 'N/A' }} |
{% endfor %}
{% else %}
No vulnerabilities detected.
{% endif %}

---

## OWASP Top 10 2025 Analysis

{% for cat, data in owasp_summary.items() %}
### {{ cat.replace('_', ' ') }} ({{ data.count }} finding{{ 's' if data.count != 1 else '' }})

{% if data.description %}_{{ data.description }}_{% endif %}

**Max Severity:** {{ data.max_severity }} | **Findings:** {{ data.count }}

{% if data.findings %}
{% for title in data.findings[:5] %}
- {{ title }}
{% endfor %}
{% if data.count > 5 %}
- _({{ data.count - 5 }} more...)_
{% endif %}
{% endif %}

{% endfor %}
{% if not owasp_summary %}
No OWASP categorized findings detected.
{% endif %}

---

## MITRE ATT&CK Enterprise Threat Coverage

> Maps detected vulnerabilities to adversary tactics and techniques that could exploit them.

{% if attack_summary %}
| Technique | Name | Tactic | Findings | Max Severity |
|-----------|------|--------|---------|-------------|
{% for tid, data in attack_summary.items() %}| [`{{ tid }}`]({{ data.url }}) | {{ data.name }} | {{ data.tactic }} | {{ data.count }} | **{{ data.max_severity }}** |
{% endfor %}

### Technique Details

{% for tid, data in attack_summary.items() %}
#### [{{ tid }}]({{ data.url }}) — {{ data.name }}

**Tactic:** {{ data.tactic }}

**Affected findings:**
{% for title in data.findings %}
- {{ title }}
{% endfor %}
{% if data.count > data.findings | length %}
- _({{ data.count - (data.findings | length) }} more...)_
{% endif %}

{% endfor %}
{% else %}
No MITRE ATT&CK techniques mapped to current findings.
{% endif %}

---

## NIST 800-53 Rev5 Control Gap Analysis

{% if nist_mapping %}
| Control ID | Family | Description | Affected Findings |
|------------|--------|-------------|------------------|
{% for control, data in nist_mapping.items() %}| **{{ control }}** | {{ data.family }} | {{ data.description }} | {{ data.count }} |
{% endfor %}
{% else %}
No NIST control gaps identified.
{% endif %}

---

## CVE / Dependency Vulnerability References

{% if cve_findings %}
| CVE ID | Package | Version | Severity | Description |
|--------|---------|---------|----------|-------------|
{% for f in cve_findings %}{% for cve in f.cve_ids %}| `{{ cve }}` | {{ f.package_name or 'N/A' }} | {{ f.package_version or 'N/A' }} | **{{ f.severity }}** | {{ f.description | truncate(80) }} |
{% endfor %}{% endfor %}
{% else %}
No known CVEs detected in dependencies.
{% endif %}

---

## Remediation Checklist

> Complete these tasks in priority order. Check off each item as it is resolved.

{% if critical_findings %}
### 🔴 Critical Priority — Fix Immediately

{% for f in critical_findings %}
- [ ] **[CRITICAL]** {% if f.file_path %}`{{ f.file_path }}{% if f.line_number %}:{{ f.line_number }}{% endif %}` — {% endif %}{{ f.title }}{% if f.remediation %}
  - _{{ f.remediation }}_{% endif %}{% if f.attack_techniques %}
  - ATT&CK: {{ f.attack_techniques[:3] | join(', ') }}{% endif %}{% if f.cve_ids %}
  - CVEs: {{ f.cve_ids | join(', ') }}{% endif %}{% if f.nist_controls %}
  - NIST: {{ f.nist_controls[:3] | join(', ') }}{% endif %}

{% endfor %}
{% endif %}

{% if high_findings %}
### 🟠 High Priority — Fix This Sprint

{% for f in high_findings %}
- [ ] **[HIGH]** {% if f.file_path %}`{{ f.file_path }}{% if f.line_number %}:{{ f.line_number }}{% endif %}` — {% endif %}{{ f.title }}{% if f.remediation %}
  - _{{ f.remediation }}_{% endif %}{% if f.attack_techniques %}
  - ATT&CK: {{ f.attack_techniques[:2] | join(', ') }}{% endif %}{% if f.nist_controls %}
  - NIST: {{ f.nist_controls[:3] | join(', ') }}{% endif %}

{% endfor %}
{% endif %}

{% if medium_findings %}
### 🟡 Medium Priority — Fix This Quarter

{% for f in medium_findings %}
- [ ] **[MEDIUM]** {% if f.file_path %}`{{ f.file_path }}{% if f.line_number %}:{{ f.line_number }}{% endif %}` — {% endif %}{{ f.title }}{% if f.remediation %}
  - _{{ f.remediation }}_{% endif %}

{% endfor %}
{% endif %}

{% if low_findings %}
### 🔵 Low Priority — Address in Backlog

{% for f in low_findings %}
- [ ] **[LOW]** {% if f.file_path %}`{{ f.file_path }}{% if f.line_number %}:{{ f.line_number }}{% endif %}` — {% endif %}{{ f.title }}

{% endfor %}
{% endif %}

{% if not critical_findings and not high_findings and not medium_findings and not low_findings %}
No actionable findings require remediation.
{% endif %}

---

## Appendix: Scanner Details

| Scanner | Status | Findings |
|---------|--------|---------|
{% for scanner, count in scanner_counts.items() %}| {{ scanner }} | ✅ Completed | {{ count }} findings |
{% endfor %}

{% if scanner_errors %}
### Scanner Warnings

{% for err in scanner_errors %}
- ⚠️ {{ err }}
{% endfor %}
{% endif %}

---

_Report generated by [Cybersecurity Agent](https://github.com/JTunnessen/Cybersecurity-Agent-for-Applications-) · NIST 800-53 Rev5 · OWASP Top 10 2025 · MITRE CVE · MITRE ATT&CK Enterprise_
