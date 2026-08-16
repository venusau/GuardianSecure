"""HTTP client wrapper and a lightweight same-host spider (crawler).

Replaces ZAP's spider with a bounded BFS crawler that discovers in-scope links.
"""
from __future__ import annotations

import re
import threading
from urllib.parse import urljoin, urlparse

import requests

from .models import ScanResult

DEFAULT_HEADERS = {
    "User-Agent": "GuardianSecure-Scanner/1.0 (+https://guardiansecure.app)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

_LINK_RE = re.compile(
    r"""(?i)<a[^>]+href\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_FORM_RE = re.compile(r"""(?i)<form[^>]*action\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


def _in_scope(url: str, base_netloc: str) -> bool:
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https", ""):
        return False
    if p.netloc and p.netloc != base_netloc:
        return False
    return True


def crawl(
    target: str,
    max_pages: int = 50,
    timeout: int = 20,
    verify_ssl: bool = True,
) -> tuple[list[str], list[str]]:
    """Bounded BFS crawl. Returns (visited_urls, error_strings)."""
    visited: set[str] = set()
    queue: list[str] = [target]
    errors: list[str] = []
    base = urlparse(target).netloc
    lock = threading.Lock()

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    def _get(url: str) -> requests.Response:
        # One retry: bot-protected or flaky origins often respond on a 2nd pass.
        try:
            return session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        except requests.RequestException:
            return session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=True)

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        try:
            resp = _get(url)
        except requests.RequestException as e:
            errors.append(f"{url}: {type(e).__name__}")
            visited.add(url)
            continue

        with lock:
            visited.add(resp.url if resp.url else url)

        if not resp.headers.get("Content-Type", "").startswith("text/html"):
            continue

        body = resp.text
        for match in _LINK_RE.findall(body) + _FORM_RE.findall(body):
            abs_url = urljoin(resp.url, match)
            if _in_scope(abs_url, base) and abs_url not in visited:
                queue.append(abs_url)

    return sorted(visited), errors


def fetch(url: str, timeout: int = 20, verify_ssl: bool = True, method: str = "GET",
          data: dict | None = None) -> requests.Response | None:
    try:
        session = requests.Session()
        session.headers.update(DEFAULT_HEADERS)
        if method.upper() == "POST":
            return session.post(url, data=data, timeout=timeout, verify=verify_ssl,
                                allow_redirects=False)
        return session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
    except requests.RequestException:
        try:
            session = requests.Session()
            session.headers.update(DEFAULT_HEADERS)
            if method.upper() == "POST":
                return session.post(url, data=data, timeout=timeout, verify=verify_ssl,
                                    allow_redirects=False)
            return session.get(url, timeout=timeout, verify=verify_ssl, allow_redirects=False)
        except requests.RequestException:
            return None
