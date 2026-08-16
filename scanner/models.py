"""GuardianSecure in-house vulnerability scanner.

Replaces the OWASP ZAP dependency with a self-contained crawler + passive/active
analysis engine that maps findings to the OWASP Top 10 (2021). No external
scanning daemon required.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class OwaspCategory(str, Enum):
    BROKEN_ACCESS_CONTROL = "A01:2021 Broken Access Control"
    CRYPTO_FAILURES = "A02:2021 Cryptographic Failures"
    INJECTION = "A03:2021 Injection"
    INSECURE_DESIGN = "A04:2021 Insecure Design"
    SECURITY_MISCONFIG = "A05:2021 Security Misconfiguration"
    VULN_COMPONENTS = "A06:2021 Vulnerable & Outdated Components"
    AUTH_FAILURES = "A07:2021 Identification & Authentication Failures"
    SOFTWARE_INTEGRITY = "A08:2021 Software & Data Integrity Failures"
    LOGGING_MONITORING = "A09:2021 Security Logging & Monitoring Failures"
    SSRF = "A10:2021 Server-Side Request Forgery (SSRF)"


@dataclass
class Finding:
    category: OwaspCategory
    severity: Severity
    title: str
    description: str
    evidence: str = ""
    url: str = ""
    remediation: str = ""
    cwe: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    started_at: float
    finished_at: float
    crawled_urls: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.finished_at - self.started_at, 2),
            "crawled_urls": self.crawled_urls,
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
