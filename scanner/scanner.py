"""Scanner orchestrator: spider -> passive -> active checks.

This is the drop-in replacement for the ZAP-based flow in the old
project/tools.py (vulnerability_matcher). It is framework-agnostic and is
invoked by the Temporal activity that runs inside a scaling worker.
"""

from __future__ import annotations

import time

from .checks.access_auth import AccessControlCheck, AuthFailuresCheck
from .checks.components import ComponentsCheck
from .checks.injection_ssrf import InjectionCheck, SsrfCheck
from .checks.transport_headers import TransportAndHeaderCheck
from .models import ScanResult
from .spider import crawl

PASSIVE_CHECKS = [TransportAndHeaderCheck(), ComponentsCheck()]
ACTIVE_CHECKS = [InjectionCheck(), SsrfCheck(), AccessControlCheck(), AuthFailuresCheck()]


class Scanner:
    def __init__(self, max_pages: int = 50, timeout: int = 20, verify_ssl: bool = True):
        self.max_pages = max_pages
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def run(self, target: str, scan_type: str = "Passive Scan") -> ScanResult:
        started = time.time()
        result = ScanResult(target=target, started_at=started, finished_at=started)

        crawled, errors = crawl(target, max_pages=self.max_pages,
                                timeout=self.timeout, verify_ssl=self.verify_ssl)
        result.crawled_urls = crawled
        result.errors.extend(errors)

        for check in PASSIVE_CHECKS:
            try:
                check.run(target, crawled, result)
            except Exception as e:  # never let one check kill the scan
                result.errors.append(f"{type(check).__name__}: {e}")

        if scan_type == "Active Scan":
            for check in ACTIVE_CHECKS:
                try:
                    check.run(target, crawled, result)
                except Exception as e:
                    result.errors.append(f"{type(check).__name__}: {e}")

        result.finished_at = time.time()
        return result
