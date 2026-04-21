from __future__ import annotations

import json

from agent.models import Finding, Severity
from scanners.base import BaseScanner

# Bandit test ID → CWE mapping
_BANDIT_CWE: dict[str, str] = {
    "B101": "CWE-617",  # assert_used
    "B102": "CWE-78",   # exec_used
    "B103": "CWE-732",  # setting_permissions
    "B104": "CWE-605",  # hardcoded_bind_all_interfaces
    "B105": "CWE-259",  # hardcoded_password_string
    "B106": "CWE-259",  # hardcoded_password_funcarg
    "B107": "CWE-259",  # hardcoded_password_default
    "B108": "CWE-377",  # probable_insecure_usage_of_temp_file
    "B110": "CWE-390",  # try_except_pass
    "B112": "CWE-390",  # try_except_continue
    "B201": "CWE-94",   # flask_debug_true
    "B202": "CWE-94",   # tarfile_unsafe_members
    "B301": "CWE-502",  # pickle
    "B302": "CWE-502",  # marshal
    "B303": "CWE-327",  # use of MD2/MD4/MD5
    "B304": "CWE-327",  # ciphers_mode
    "B305": "CWE-327",  # cipher_modes
    "B306": "CWE-377",  # mktemp_q
    "B307": "CWE-78",   # eval
    "B308": "CWE-79",   # mark_safe
    "B310": "CWE-601",  # urllib_urlopen
    "B311": "CWE-330",  # random
    "B312": "CWE-605",  # telnetlib
    "B313": "CWE-611",  # xml_bad_cElementTree
    "B314": "CWE-611",  # xml_bad_ElementTree
    "B315": "CWE-611",  # xml_bad_expatreader
    "B316": "CWE-611",  # xml_bad_expatbuilder
    "B317": "CWE-611",  # xml_bad_sax
    "B318": "CWE-611",  # xml_bad_minidom
    "B319": "CWE-611",  # xml_bad_pulldom
    "B320": "CWE-611",  # xml_bad_etree
    "B321": "CWE-321",  # ftp_lib
    "B322": "CWE-78",   # input (Python 2)
    "B323": "CWE-295",  # unverified_context
    "B324": "CWE-916",  # hashlib
    "B325": "CWE-330",  # mktemp
    "B401": "CWE-319",  # import_telnetlib
    "B402": "CWE-321",  # import_ftplib
    "B403": "CWE-502",  # import_pickle
    "B404": "CWE-78",   # import_subprocess
    "B405": "CWE-611",  # import_xml_etree
    "B406": "CWE-611",  # import_xml_sax
    "B407": "CWE-611",  # import_xml_expat
    "B408": "CWE-611",  # import_xml_minidom
    "B409": "CWE-611",  # import_xml_pulldom
    "B410": "CWE-611",  # import_lxml
    "B411": "CWE-200",  # import_xmlrpclib
    "B412": "CWE-327",  # import_httpoxy
    "B413": "CWE-327",  # import_pycrypto
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B502": "CWE-326",  # ssl_with_bad_version
    "B503": "CWE-326",  # ssl_with_bad_defaults
    "B504": "CWE-326",  # ssl_with_no_version
    "B505": "CWE-326",  # weak_cryptographic_key
    "B506": "CWE-20",   # yaml_load
    "B507": "CWE-295",  # ssh_no_host_key_verification
    "B601": "CWE-78",   # paramiko_calls
    "B602": "CWE-78",   # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_with_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-89",   # hardcoded_sql_expressions
    "B609": "CWE-78",   # linux_commands_wildcard_injection
    "B610": "CWE-89",   # django_extra_used
    "B611": "CWE-89",   # django_rawsql_used
    "B701": "CWE-94",   # jinja2_autoescape_false
    "B702": "CWE-79",   # use_of_mako_templates
    "B703": "CWE-79",   # django_mark_safe
}

_BANDIT_SEVERITY_MAP: dict[str, Severity] = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class BanditScanner(BaseScanner):
    def scan(self, repo_path: str) -> list[Finding]:
        cmd = ["bandit", "-r", repo_path, "-f", "json", "-ll", "--quiet"]
        stdout, stderr, rc = self.run_subprocess(cmd, repo_path)

        if not stdout:
            return []

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return []

        findings = []
        for issue in data.get("results", []):
            test_id = issue.get("test_id", "")
            cwe = _BANDIT_CWE.get(test_id)
            cwe_ids = [cwe] if cwe else []

            severity_str = issue.get("issue_severity", "LOW").upper()
            severity = _BANDIT_SEVERITY_MAP.get(severity_str, Severity.LOW)

            finding = Finding(
                source="bandit",
                title=issue.get("test_name", "Unknown Issue"),
                description=issue.get("issue_text", ""),
                severity=severity,
                file_path=issue.get("filename", ""),
                line_number=issue.get("line_number"),
                cwe_ids=cwe_ids,
                references=[issue.get("more_info", "")],
            )
            findings.append(finding)

        return findings
