"""A02 / A05: TLS configuration, security headers & cookie hardening.

Passive checks performed on the root response and discovered pages.
"""

from __future__ import annotations

from .base import BaseCheck
from ..models import OwaspCategory, Severity
from ..spider import fetch

REQUIRED_HEADERS = {
    "Strict-Transport-Security": "A02",
    "Content-Security-Policy": "A05",
    "X-Content-Type-Options": "A05",
    "X-Frame-Options": "A05",
    "Referrer-Policy": "A05",
}

SECURE_COOKIE_FLAGS = ("secure", "httponly", "samesite")


class TransportAndHeaderCheck(BaseCheck):
    category = OwaspCategory.SECURITY_MISCONFIG
    title = "Transport Security & Security Headers"

    def run(self, target: str, crawled: list[str], result) -> None:
        sample = crawled[:10] if crawled else [target]
        for url in sample:
            resp = fetch(url)
            if resp is None:
                continue

            if url.startswith("http://"):
                self.add(
                    result, Severity.HIGH,
                    "Insecure transport (HTTP)",
                    "Target served over plain HTTP; traffic can be intercepted.",
                    evidence=url, url=url,
                    remediation="Serve exclusively over HTTPS with HSTS.",
                    cwe="CWE-319",
                )

            headers = {k.lower(): v for k, v in resp.headers.items()}
            for header, cat in REQUIRED_HEADERS.items():
                if header.lower() not in headers:
                    sev = Severity.MEDIUM if cat == "A05" else Severity.MEDIUM
                    self.add(
                        result, sev,
                        f"Missing security header: {header}",
                        f"Response for {url} does not include the {header} header.",
                        evidence=url, url=url,
                        remediation=f"Add the {header} response header.",
                        cwe="CWE-693",
                    )

            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                low = set_cookie.lower()
                missing = [f for f in SECURE_COOKIE_FLAGS if f not in low]
                if missing:
                    self.add(
                        result, Severity.LOW,
                        "Insecure cookie attributes",
                        f"Cookie missing flags: {', '.join(missing)}.",
                        evidence=set_cookie[:120], url=url,
                        remediation="Set Secure, HttpOnly and SameSite on session cookies.",
                        cwe="CWE-614",
                    )

            server = headers.get("server", "")
            if server:
                self.add(
                    result, Severity.INFO,
                    "Server banner disclosed",
                    f"Server header reveals software: {server}",
                    evidence=server, url=url,
                    remediation="Suppress or genericize the Server header.",
                    cwe="CWE-200",
                )
