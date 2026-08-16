"""Base class for all scanner checks."""

from __future__ import annotations

from ..models import Finding, OwaspCategory, ScanResult, Severity


class BaseCheck:
    category: OwaspCategory = OwaspCategory.INSECURE_DESIGN
    title: str = "Base Check"

    def run(self, target: str, crawled: list[str], result: ScanResult) -> None:
        raise NotImplementedError

    def add(self, result: ScanResult, severity: Severity, title: str,
            description: str, evidence: str = "", url: str = "",
            remediation: str = "", cwe: str = "") -> None:
        result.add(Finding(
            category=self.category, severity=severity, title=title,
            description=description, evidence=evidence, url=url,
            remediation=remediation, cwe=cwe,
        ))
