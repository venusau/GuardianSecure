"""A03: Injection (Reflected XSS & SQL Injection) and A10: SSRF.

Active checks: inject probe payloads into query parameters discovered via the
crawler and observe the responses for reflected/executable evidence.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .base import BaseCheck
from ..models import OwaspCategory, Severity
from ..spider import fetch

XSS_PAYLOAD = "<script>gs_xss_1337</script>"
XSS_EVIDENCE = re.compile(r"<script>gs_xss_1337</script>", re.IGNORECASE)

SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "1'--", "') OR ('1'='1"]
SQLI_SIGNATURES = [
    re.compile(r"(?:SQL syntax|mysql_fetch|ORA-\d{5}|Unclosed quotation mark|"
               r"SQLite3::|syntax error.*near|pg_query)", re.IGNORECASE),
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:80/",
    "http://127.0.0.1:22/",
]


def _inject_params(url: str, payload: str) -> str:
    parts = urlparse(url)
    qs = parse_qs(parts.query)
    if not qs:
        qs = {"q": [payload], "id": [payload], "search": [payload]}
    else:
        for k in qs:
            qs[k] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parts._replace(query=new_query))


class InjectionCheck(BaseCheck):
    category = OwaspCategory.INJECTION
    title = "Injection (XSS / SQLi)"

    def run(self, target: str, crawled: list[str], result) -> None:
        targets = crawled[:15] if crawled else [target]

        for url in targets:
            # Reflected XSS
            test_url = _inject_params(url, XSS_PAYLOAD)
            resp = fetch(test_url)
            if resp and XSS_EVIDENCE.search(resp.text):
                self.add(
                    result, Severity.HIGH,
                    "Reflected Cross-Site Scripting (XSS)",
                    "User input is reflected into the response without encoding, "
                    "allowing script injection.",
                    evidence=test_url, url=test_url,
                    remediation="Contextually encode output and validate input; "
                                "deploy a Content-Security-Policy.",
                    cwe="CWE-79",
                )

            # SQL Injection
            for payload in SQLI_PAYLOADS:
                sql_url = _inject_params(url, payload)
                r = fetch(sql_url)
                if not r:
                    continue
                for sig in SQLI_SIGNATURES:
                    if sig.search(r.text):
                        self.add(
                            result, Severity.CRITICAL,
                            "SQL Injection",
                            "Response matches a database error signature, "
                            "indicating injectable input.",
                            evidence=f"{sql_url} -> {sig.pattern[:30]}", url=sql_url,
                            remediation="Use parameterized queries / ORM and "
                                        "input validation.",
                            cwe="CWE-89",
                        )
                        break


class SsrfCheck(BaseCheck):
    category = OwaspCategory.SSRF
    title = "Server-Side Request Forgery"

    def run(self, target: str, crawled: list[str], result) -> None:
        targets = crawled[:10] if crawled else [target]
        for url in targets:
            for payload in SSRF_PAYLOADS:
                test_url = _inject_params(url, payload)
                resp = fetch(test_url, timeout=5)
                if resp is None:
                    continue
                if resp.status_code < 400 and ("169.254.169.254" in payload
                                               or "root:" in resp.text
                                               or "SSH" in resp.text):
                    self.add(
                        result, Severity.HIGH,
                        "Potential SSRF",
                        "Server fetched an internal/cloud-metadata resource based "
                        "on attacker-controlled input.",
                        evidence=test_url, url=test_url,
                        remediation="Allowlist outbound destinations; block link-local "
                                    "and internal ranges.",
                        cwe="CWE-918",
                    )
                    break
