"""A06: Vulnerable & Outdated Components.

Fingerprints server/technology banners and flags known-old signatures.
Pairs with A08 (integrity) where SRI / unsigned assets are detected.
"""

from __future__ import annotations

import re

from .base import BaseCheck
from ..models import OwaspCategory, Severity
from ..spider import fetch

OUTDATED_SIGS = [
    (re.compile(r"nginx/1\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17)\.", re.I), "nginx"),
    (re.compile(r"Apache/2\.2\.", re.I), "Apache 2.2"),
    (re.compile(r"PHP/5\.", re.I), "PHP 5.x"),
    (re.compile(r"jQuery/1\.", re.I), "jQuery 1.x"),
    (re.compile(r"jQuery/2\.", re.I), "jQuery 2.x"),
]

SRI_RE = re.compile(r"""<script[^>]+src=[^>]+integrity=["']""", re.IGNORECASE)


class ComponentsCheck(BaseCheck):
    category = OwaspCategory.VULN_COMPONENTS
    title = "Vulnerable & Outdated Components"

    def run(self, target: str, crawled: list[str], result) -> None:
        sample = crawled[:10] if crawled else [target]
        for url in sample:
            resp = fetch(url)
            if resp is None:
                continue
            headers = {k.lower(): v for k, v in resp.headers.items()}
            banner = f"{headers.get('server','')} {headers.get('x-powered-by','')}"
            for sig, name in OUTDATED_SIGS:
                if sig.search(banner):
                    self.add(
                        result, Severity.MEDIUM,
                        f"Outdated component: {name}",
                        f"Response banner indicates an outdated technology: {name}.",
                        evidence=banner.strip(), url=url,
                        remediation="Upgrade to a supported, patched version and "
                                    "remove version banners.",
                        cwe="CWE-1104",
                    )

            if resp.headers.get("Content-Type", "").startswith("text/html"):
                scripts = re.findall(r"<script[^>]+src=[^>]+>", resp.text, re.I)
                if scripts and not any(SRI_RE.search(s) for s in scripts):
                    self.add(
                        result, Severity.LOW,
                        "Missing Subresource Integrity (SRI)",
                        "External scripts are loaded without integrity attributes, "
                        "an A08 data-integrity risk.",
                        evidence=url, url=url,
                        remediation="Add integrity + crossorigin attributes to "
                                    "external script/style tags.",
                        cwe="CWE-353",
                    )
