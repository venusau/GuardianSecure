"""pdf_generation microservice.

Standalone Flask service that renders a GuardianSecure vulnerability report
as a branded PDF. Consumed by the API gateway over HTTP:

  POST /generate  (scan result JSON) -> application/pdf
  GET  /health                        -> {"service": "pdf_generation", "status": "ok"}

Kept intentionally stateless so it can be scaled independently.
"""

from __future__ import annotations

import io
import os
from datetime import datetime, timezone

from flask import Flask, jsonify, request, Response
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

app = Flask(__name__)

# ---- brand palette -------------------------------------------------------
INK = colors.HexColor("#0F172A")        # slate-950
ACCENT = colors.HexColor("#00E0A4")     # GuardianSecure emerald
BG = colors.HexColor("#F8FAFC")
BORDER = colors.HexColor("#E2E8F0")
MUTED = colors.HexColor("#64748B")
REM_BG = colors.HexColor("#ECFDF5")
REM_TX = colors.HexColor("#065F46")

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#E11D48"),
    "HIGH": colors.HexColor("#EA580C"),
    "MEDIUM": colors.HexColor("#D97706"),
    "LOW": colors.HexColor("#0284C7"),
    "INFO": colors.HexColor("#64748B"),
}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _esc(text: str) -> str:
    return (
        str(text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _fmt_ts(epoch) -> str:
    if not epoch:
        return "-"
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
    except (TypeError, ValueError, OSError):
        return "-"


def _fmt_dur(sec) -> str:
    if not sec:
        return "-"
    sec = float(sec)
    if sec < 60:
        return f"{sec:.1f}s"
    return f"{int(sec // 60)}m {round(sec % 60)}s"


def _styles():
    getSampleStyleSheet()
    return {
        "brand": ParagraphStyle("brand", fontName="Helvetica-Bold", fontSize=13, textColor=ACCENT),
        "report_title": ParagraphStyle("report_title", fontName="Helvetica-Bold", fontSize=20, textColor=colors.white, leading=24),
        "report_sub": ParagraphStyle("report_sub", fontName="Helvetica", fontSize=9, textColor=colors.HexColor("#94A3B8"), leading=12),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13, textColor=INK, spaceAfter=5),
        "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=7.5, textColor=MUTED, leading=10),
        "value": ParagraphStyle("value", fontName="Helvetica", fontSize=9.5, textColor=INK, leading=13),
        "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=10.5, textColor=INK, leading=14),
        "mono": ParagraphStyle("mono", fontName="Courier", fontSize=8.5, textColor=colors.HexColor("#334155"), leading=12, wordWrap="CJK"),
        "sev_num": ParagraphStyle("sev_num", fontName="Helvetica-Bold", fontSize=18, textColor=colors.white, alignment=TA_CENTER, leading=21),
        "sev_label": ParagraphStyle("sev_label", fontName="Helvetica-Bold", fontSize=7.5, textColor=colors.white, alignment=TA_CENTER, leading=9),
        "badge": ParagraphStyle("badge", fontName="Helvetica-Bold", fontSize=8, textColor=colors.white, alignment=TA_CENTER, leading=10),
        "foot": ParagraphStyle("foot", fontName="Helvetica", fontSize=7.5, textColor=MUTED),
    }


def _header_band(st) -> Table:
    t = Table(
        [
            [Paragraph("GUARDIANSECURE", st["brand"]),
             Paragraph("Vulnerability Assessment Report", st["report_title"])],
            ["", Paragraph("Self-hosted scanner · OWASP Top-10 checks · No data leaves your infrastructure", st["report_sub"])],
        ],
        colWidths=[40 * mm, None],
    )
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), INK),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING", (0, 0), (-1, -1), 14),
    ]))
    return t


def _meta_grid(result, st) -> Table:
    rows = [
        ["TARGET URL", result.get("target") or "-", "SCAN MODE", result.get("scan_mode") or "-"],
        ["STARTED", _fmt_ts(result.get("started_at")), "DURATION", _fmt_dur(result.get("duration_seconds"))],
        ["URLS CRAWLED", str(len(result.get("crawled_urls") or [])), "FINDINGS", str(len(result.get("findings") or []))],
    ]
    data = []
    for r in rows:
        data.append([
            Paragraph(r[0], st["label"]),
            Paragraph(f"<font face='Courier'>{_esc(r[1])}</font>", st["value"]),
            Paragraph(r[2], st["label"]),
            Paragraph(f"<font face='Courier'>{_esc(r[3])}</font>", st["value"]),
        ])
    t = Table(data, colWidths=[26 * mm, None, 26 * mm, None])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), BG),
        ("BOX", (0, 0), (-1, -1), 0.8, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _severity_box(sev: str, count: int, st) -> Table:
    color = SEV_COLORS.get(sev, SEV_COLORS["INFO"])
    box = Table(
        [
            [Paragraph(str(count), st["sev_num"])],
            [Paragraph(sev, st["sev_label"])],
        ],
        colWidths=[30 * mm],
    )
    box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BOX", (0, 0), (-1, -1), 0, color),
    ]))
    return box


def _summary_row(result, st) -> Table:
    s = result.get("summary") or {}
    boxes = [_severity_box(sev, int(s.get(sev, 0) or 0), st) for sev in SEV_ORDER]
    grid = Table([boxes], colWidths=[30 * mm] * 5)
    grid.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 1.5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 1.5),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return grid


def _finding_card(f, idx, total, st) -> Table:
    sev = (f.get("severity") or "INFO").upper()
    color = SEV_COLORS.get(sev, SEV_COLORS["INFO"])

    badge = Table(
        [[Paragraph(sev, st["badge"])]],
        colWidths=[24 * mm],
    )
    badge.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))

    head_right = Table([[badge]], colWidths=[None])
    head_right.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "RIGHT")]))

    rows = [
        [Paragraph(f"FINDING {idx} OF {total}", st["label"]), head_right],
        [Paragraph(_esc(f.get("title") or "Untitled finding"), st["title"]), ""],
    ]
    meta = " · ".join(
        x for x in [
            f.get("category"),
            f"CWE-{f.get('cwe')}" if f.get("cwe") else None,
        ] if x
    )
    if meta:
        rows.append([Paragraph("OWASP", st["label"]), Paragraph(_esc(meta), st["value"])])
    if f.get("url"):
        rows.append([Paragraph("URL", st["label"]), Paragraph(_esc(f["url"]), st["mono"])])
    if f.get("description"):
        rows.append([Paragraph("DESCRIPTION", st["label"]), Paragraph(_esc(f["description"]), st["value"])])
    if f.get("evidence"):
        rows.append([Paragraph("EVIDENCE", st["label"]), Paragraph(_esc(f["evidence"]), st["mono"])])
    rows.append([Paragraph("REMEDIATION", st["label"]), Paragraph(_esc(f.get("remediation") or "-"), st["value"])])

    t = Table(rows, colWidths=[30 * mm, None])
    style = [
        ("BACKGROUND", (0, 0), (-1, -1), BG),
        ("BOX", (0, 0), (-1, -1), 0.8, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]
    rem_row = len(rows) - 1
    style += [
        ("BACKGROUND", (0, rem_row), (-1, rem_row), REM_BG),
        ("TEXTCOLOR", (1, rem_row), (1, rem_row), REM_TX),
    ]
    t.setStyle(TableStyle(style))
    return t


class NumberedCanvas(pdfcanvas.Canvas):
    """Adds 'Page X of Y' + footer line to every page."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(MUTED)
            self.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {self._pageNumber} of {total}")
            self.drawString(18 * mm, 10 * mm, "GuardianSecure · Confidential")
            super().showPage()
        super().save()


def build_pdf(result: dict) -> bytes:
    st = _styles()
    buf = io.BytesIO()
    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title="GuardianSecure Vulnerability Assessment Report",
        author="GuardianSecure",
    )
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="page", frames=[frame])])

    story = [
        _header_band(st),
        Spacer(1, 8 * mm),
        _meta_grid(result, st),
        Spacer(1, 8 * mm),
        Paragraph("Executive Summary", st["h2"]),
        _summary_row(result, st),
        Spacer(1, 8 * mm),
        Paragraph("Detailed Findings", st["h2"]),
    ]

    findings = result.get("findings") or []
    if not findings:
        story.append(Paragraph("No vulnerabilities were detected for the configured checks.", st["value"]))
    for i, f in enumerate(findings, 1):
        story.append(KeepTogether(_finding_card(f, i, len(findings), st)))
        story.append(Spacer(1, 5 * mm))

    story += [
        Spacer(1, 3 * mm),
        HRFlowable(width="100%", thickness=0.6, color=BORDER),
        Spacer(1, 3 * mm),
        Paragraph(
            "Generated by GuardianSecure — self-hosted, no data leaves your infrastructure.",
            st["foot"],
        ),
    ]
    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


@app.get("/health")
def health():
    return jsonify({"service": "pdf_generation", "status": "ok"})


@app.post("/generate")
def generate():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON scan result body required"}), 400
    try:
        pdf = build_pdf(data)
    except Exception:
        app.logger.exception("PDF build failed")
        return jsonify({"error": "PDF generation failed"}), 500
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="report.pdf"'},
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)