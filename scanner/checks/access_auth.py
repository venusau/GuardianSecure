"""A01: Broken Access Control and A07: Auth Failures.

Probes common privileged/unauthenticated paths and tests login endpoint
protection against brute force (no rate-limit / no lockout signalling).
"""

from __future__ import annotations

from .base import BaseCheck
from ..models import OwaspCategory, Severity
from ..spider import fetch

SENSITIVE_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/.env", "/config", "/phpinfo.php",
    "/.git/HEAD", "/api/users", "/dashboard", "/account", "/debug",
]


class AccessControlCheck(BaseCheck):
    category = OwaspCategory.BROKEN_ACCESS_CONTROL
    title = "Broken Access Control"

    def run(self, target: str, crawled: list[str], result) -> None:
        base = target.rstrip("/")
        for path in SENSITIVE_PATHS:
            url = base + path
            resp = fetch(url)
            if resp is None:
                continue
            if resp.status_code == 200 and "login" not in (resp.url or "").lower():
                self.add(
                    result, Severity.HIGH,
                    f"Accessible sensitive path: {path}",
                    "A path that typically requires authorization returned 200 "
                    "without redirecting to authentication.",
                    evidence=f"{url} -> {resp.status_code}", url=url,
                    remediation="Enforce authentication/authorization on all "
                                "privileged routes; return 401/403.",
                    cwe="CWE-285",
                )


class AuthFailuresCheck(BaseCheck):
    category = OwaspCategory.AUTH_FAILURES
    title = "Authentication Weaknesses"

    def run(self, target: str, crawled: list[str], result) -> None:
        base = target.rstrip("/")
        login_url = base + "/login"
        resp = fetch(login_url)
        if resp is None:
            return
        headers = {k.lower(): v for k, v in resp.headers.items()}
        has_ratelimit = any(
            h in headers for h in ("retry-after", "x-ratelimit-limit")
        )
        if not has_ratelimit:
            self.add(
                result, Severity.MEDIUM,
                "No brute-force protection on login",
                "Login endpoint does not advertise rate limiting / lockout.",
                evidence=login_url, url=login_url,
                remediation="Implement rate limiting, account lockout and "
                            "CAPTCHA on authentication endpoints.",
                cwe="CWE-307",
            )
