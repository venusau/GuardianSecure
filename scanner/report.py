"""Report rendering: JSON + lightweight HTML (replaces ZAP PDF report).

Operates on the plain dict produced by ScanResult.to_dict() so it works with
persisted scan results without reconstructing enum objects.
"""

from __future__ import annotations

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def to_json(result: dict) -> dict:
    return result


def to_html(result: dict) -> str:
    findings = result.get("findings", [])
    summary = result.get("summary", {})

    rows = []
    for sev in SEVERITY_ORDER:
        for f in findings:
            if f.get("severity") != sev:
                continue
            rows.append(
                f"<tr class='{sev.lower()}'><td>{f.get('severity')}</td>"
                f"<td>{f.get('category')}</td><td>{f.get('title')}</td>"
                f"<td>{f.get('url') or '-'}</td><td>{f.get('evidence') or '-'}</td>"
                f"<td>{f.get('remediation') or '-'}</td></tr>"
            )

    summary_html = " ".join(
        f"<b>{k}</b>:{v}" for k, v in summary.items()
    ) or "<b>no data</b>"

    return f"""<!doctype html><html><head><meta charset='utf-8'>
<style>body{{font-family:Inter,system-ui,sans-serif;margin:2rem;color:#0b0f17}}
h2{{margin-bottom:.2rem}} table{{border-collapse:collapse;width:100%;margin-top:1rem}}
td,th{{border:1px solid #ccc;padding:6px;font-size:13px;text-align:left}}
.critical{{background:#fdd}} .high{{background:#fec}} .medium{{background:#ffd}}
.low{{background:#efe}} .info{{background:#eef}}</style></head>
<body><h2>GuardianSecure Scan Report</h2>
<p><b>Target:</b> {result.get('target','-')}</p>
<p><b>Duration:</b> {result.get('duration_seconds','?')}s &middot;
<b>Pages crawled:</b> {len(result.get('crawled_urls',[]))}</p>
<p><b>Summary:</b> {summary_html}</p>
<table><tr><th>Severity</th><th>OWASP</th><th>Title</th><th>URL</th>
<th>Evidence</th><th>Remediation</th></tr>{''.join(rows)}</table>
</body></html>"""
