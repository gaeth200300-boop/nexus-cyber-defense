"""PDF report renderer (ReportLab) with real Arabic shaping.

Arabic strings are reshaped (arabic-reshaper) and re-ordered (python-bidi)
before they reach ReportLab, and we register a Unicode TTF that actually
contains Arabic glyphs. If no such font exists on the machine, the PDF renders
the English text and *says so* — it never prints garbled Arabic glyphs.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..core.constants import SEVERITY_COLORS, SEVERITY_LABELS

log = logging.getLogger("nexus.reports.pdf")

ARABIC_RE = re.compile(r"[\u0600-\u06FF]")

FONT_CANDIDATES: list[tuple[str, str]] = [
    (r"C:\Windows\Fonts\segoeui.ttf", r"C:\Windows\Fonts\segoeuib.ttf"),
    (r"C:\Windows\Fonts\arial.ttf", r"C:\Windows\Fonts\arialbd.ttf"),
    (r"C:\Windows\Fonts\tahoma.ttf", r"C:\Windows\Fonts\tahomabd.ttf"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/Library/Fonts/Arial.ttf", "/Library/Fonts/Arial Bold.ttf"),
]

_REGISTERED: dict[str, str] = {}


def _register_fonts() -> tuple[str, str, bool]:
    """Return (body_font, bold_font, unicode_capable)."""
    if _REGISTERED:
        return _REGISTERED["body"], _REGISTERED["bold"], _REGISTERED["unicode"] == "1"
    for regular, bold in FONT_CANDIDATES:
        if Path(regular).exists():
            try:
                pdfmetrics.registerFont(TTFont("NexusBody", regular))
                bold_path = bold if Path(bold).exists() else regular
                pdfmetrics.registerFont(TTFont("NexusBold", bold_path))
                _REGISTERED.update({"body": "NexusBody", "bold": "NexusBold", "unicode": "1"})
                return "NexusBody", "NexusBold", True
            except Exception as exc:  # pragma: no cover - font file quirks
                log.warning("could not register font %s: %s", regular, exc)
    _REGISTERED.update({"body": "Helvetica", "bold": "Helvetica-Bold", "unicode": "0"})
    return "Helvetica", "Helvetica-Bold", False


def _shape(text: str, unicode_ok: bool) -> str:
    """Shape Arabic for ReportLab; degrade to a clear note when unsupported."""
    if not text:
        return ""
    if not ARABIC_RE.search(text):
        return text
    if not unicode_ok:
        return "[Arabic text requires a Unicode font on this machine — see the HTML/JSON report]"
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display

        # shape each line separately so mixed content keeps its structure
        lines = []
        for line in str(text).split("\n"):
            if ARABIC_RE.search(line):
                lines.append(get_display(arabic_reshaper.reshape(line)))
            else:
                lines.append(line)
        return "\n".join(lines)
    except Exception as exc:  # pragma: no cover
        log.debug("arabic shaping failed: %s", exc)
        return text


def _xml(text: Any, unicode_ok: bool = True) -> str:
    """Escape XML-sensitive characters for Paragraph markup."""
    value = _shape(str(text if text is not None else ""), unicode_ok)
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_pdf(data: dict[str, Any], path: Path) -> None:
    body_font, bold_font, unicode_ok = _register_fonts()
    report = data["report"]
    project = data["project"]
    summary = data["summary"]

    styles = getSampleStyleSheet()
    base = ParagraphStyle("base", parent=styles["Normal"], fontName=body_font, fontSize=9, leading=13, textColor=colors.HexColor("#0f172a"))
    h1 = ParagraphStyle("h1", parent=base, fontName=bold_font, fontSize=20, leading=25, textColor=colors.HexColor("#1e1b4b"))
    h2 = ParagraphStyle("h2", parent=base, fontName=bold_font, fontSize=13, leading=17, spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#5b21b6"))
    h3 = ParagraphStyle("h3", parent=base, fontName=bold_font, fontSize=10.5, leading=14, spaceBefore=8, spaceAfter=3)
    small = ParagraphStyle("small", parent=base, fontSize=8, textColor=colors.HexColor("#64748b"))
    cell = ParagraphStyle("cell", parent=base, fontSize=8, leading=11)
    cell_b = ParagraphStyle("cellb", parent=cell, fontName=bold_font)
    ar = ParagraphStyle("ar", parent=base, alignment=TA_RIGHT, fontSize=9.5)
    pre = ParagraphStyle("pre", parent=base, fontName="Courier", fontSize=7, leading=9, textColor=colors.HexColor("#334155"))

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=18 * mm,
        bottomMargin=16 * mm,
        title=report["title"][:120],
        author=f"{data['platform']['name']} v{data['platform']['version']}",
        subject="Authorized security assessment report",
    )

    def on_page(canvas, _doc):
        canvas.saveState()
        canvas.setFont(body_font, 7.5)
        canvas.setFillColor(colors.HexColor("#94a3b8"))
        canvas.drawString(16 * mm, A4[1] - 11 * mm, f"{data['platform']['name']} — {report['kind']} report — {project['name']}"[:130])
        canvas.drawRightString(A4[0] - 16 * mm, A4[1] - 11 * mm, data["platform"]["classification"][:80])
        canvas.drawCentredString(A4[0] / 2, 9 * mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    story: list[Any] = []

    # ----------------------------------------------------------------- cover
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(_xml("NEXUS CYBER DEFENSE", unicode_ok), small))
    story.append(Paragraph(_xml("نيكسوس للدفاع السيبراني", unicode_ok), ar))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(_xml(report["title"], unicode_ok), h1))
    story.append(HRFlowable(width="100%", thickness=1.4, color=colors.HexColor("#7c3aed"), spaceAfter=6))
    meta_rows = [
        ["Project · المشروع", _xml(project["name"], unicode_ok)],
        ["Project kind · نوع المشروع", _xml(project.get("kind", ""), unicode_ok)],
        ["Report kind · نوع التقرير", _xml(report["kind"], unicode_ok)],
        ["Generated · تاريخ الإنشاء", _xml(report["generated_at"], unicode_ok)],
        ["Report version · الإصدار", _xml(report["version"], unicode_ok)],
        ["Platform · المنصة", _xml(f"{data['platform']['name']} v{data['platform']['version']}", unicode_ok)],
    ]
    meta_table = Table(
        [[Paragraph(_xml(a, unicode_ok), cell_b), Paragraph(b, cell)] for a, b in meta_rows],
        colWidths=[55 * mm, None],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 4 * mm))
    if ARABIC_RE.search(project.get("description", "") or ""):
        story.append(Paragraph(_xml(project.get("description", ""), unicode_ok), ar))
    story.append(Spacer(1, 6 * mm))

    # ------------------------------------------------------------ summary
    story.append(Paragraph(_xml("Executive summary · الملخص التنفيذي", unicode_ok), h2))
    if ARABIC_RE.search("الملخص") and not unicode_ok:
        story.append(Paragraph(_xml("Arabic requires a Unicode font on this machine.", unicode_ok), small))
    summary_rows = [
        ["Findings in report", "Critical + High", "Verified", "Assets", "Services", "Scans"],
        [
            str(summary["findings_in_report"]),
            str(summary["critical_high"]),
            str(summary["verified_findings"]),
            str(summary["assets"]),
            str(summary["services"]),
            str(summary["scans"]),
        ],
    ]
    summary_table = Table(summary_rows, colWidths=[28 * mm] * 6)
    summary_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), bold_font),
                ("FONTNAME", (0, 1), (-1, 1), bold_font),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 3 * mm))

    sev_rows = [[Paragraph(_xml("Severity · الخطورة", unicode_ok), cell_b), Paragraph(_xml("Count · العدد", unicode_ok), cell_b)]]
    for severity in ("critical", "high", "medium", "low", "info"):
        label = SEVERITY_LABELS.get(severity, {})
        sev_rows.append(
            [
                Paragraph(_xml(f"{label.get('en', severity)} · {label.get('ar', '')}", unicode_ok), cell),
                Paragraph(str(summary["severity_counts"].get(severity, 0)), cell),
            ]
        )
    sev_rows.append(
        [
            Paragraph(_xml("Total · الإجمالي", unicode_ok), cell_b),
            Paragraph(str(sum(int(v) for v in summary["severity_counts"].values())), cell_b),
        ]
    )
    sev_table = Table(sev_rows, colWidths=[60 * mm, 25 * mm])
    sev_style = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
        ("FONTNAME", (0, 0), (-1, 0), bold_font),
        ("FONTNAME", (0, -1), (-1, -1), bold_font),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
    ]
    sev_table.setStyle(TableStyle(sev_style))
    story.append(sev_table)

    # ------------------------------------------------------------ scope
    story.append(Paragraph(_xml("Scope & authorization · النطاق والتفويض", unicode_ok), h2))
    scope_rows = [["Kind", "Value", "Subdomains", "Active", "Authorization ref"]]
    for scope in data["scopes"]:
        scope_rows.append(
            [
                _xml(scope["kind"], unicode_ok),
                _xml(scope["value"], unicode_ok),
                "yes" if scope["include_subdomains"] else "no",
                "yes" if scope["allow_active"] else "no",
                _xml(scope.get("authorization_ref") or "—", unicode_ok),
            ]
        )
    if len(scope_rows) == 1:
        scope_rows.append(["—", "No active scope entries", "—", "—", "—"])
    scope_table = Table(scope_rows, colWidths=[18 * mm, 60 * mm, 20 * mm, 16 * mm, 55 * mm])
    scope_table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("FONTNAME", (0, 0), (-1, 0), bold_font),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(scope_table)

    # ------------------------------------------------------------ scans
    if data["scans"]:
        story.append(Paragraph(_xml("Scans included · الفحوصات المشمولة", unicode_ok), h2))
        scan_rows = [["Name", "Kind / profile", "Status", "Window"]]
        for scan in data["scans"]:
            scan_rows.append(
                [
                    _xml(scan["name"], unicode_ok),
                    _xml(f"{scan['kind']} / {scan['profile']}", unicode_ok),
                    _xml(f"{scan['status']} ({scan['progress']}%)", unicode_ok),
                    _xml(f"{(scan['started_at'] or '')[:19]} → {(scan['finished_at'] or '')[:19]}", unicode_ok),
                ]
            )
        scan_table = Table(scan_rows, colWidths=[45 * mm, 40 * mm, 30 * mm, 54 * mm])
        scan_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e2e8f0")),
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                    ("FONTNAME", (0, 0), (-1, 0), bold_font),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(scan_table)

    story.append(PageBreak())

    # ------------------------------------------------------------ findings
    story.append(Paragraph(_xml(f"Findings · النتائج ({len(data['findings'])})", unicode_ok), h2))
    if not data["findings"]:
        story.append(Paragraph(_xml("No findings matched this report's filters.", unicode_ok), base))

    for index, item in enumerate(data["findings"], start=1):
        severity = item["severity"]
        color = colors.HexColor(SEVERITY_COLORS.get(severity, "#64748b"))
        header = Paragraph(
            f'<font color="{color.hexval()}"><b>{index}. {_xml(item["title"], unicode_ok)}</b></font>',
            h3,
        )
        chips = Paragraph(
            _xml(
                f"severity: {severity} · confidence: {item['confidence']} · status: {item['status']}"
                + (" · verified" if item.get("verified") else "")
                + (" · active check" if item.get("active_check") else "")
                + (f" · CVSS {item['cvss_score']}" if item.get("cvss_score") is not None else "")
                + (f" · {item['cwe']}" if item.get("cwe") else "")
                + (f" · {item['cve']}" if item.get("cve") else ""),
                unicode_ok,
            ),
            small,
        )
        target = Paragraph(
            _xml(f"target: {item['target']}" + (f" · location: {item['location']}" if item.get("location") else ""), unicode_ok),
            small,
        )
        blocks = [header, chips, target]
        for label, field in (("Description", "description"), ("Impact", "impact"), ("Remediation", "remediation")):
            if item.get(field):
                blocks.append(Paragraph(_xml(f"{label}: {item[field]}", unicode_ok), cell))
        if item.get("intel"):
            intel_text = ", ".join(
                f"{link['cve']} ({link.get('match_type', 'inferred')}{', KEV' if link.get('kev') else ''})"
                for link in item["intel"]
            )
            blocks.append(Paragraph(_xml(f"Intel: {intel_text}", unicode_ok), cell))
        if item.get("references"):
            blocks.append(Paragraph(_xml("References: " + " | ".join(item["references"][:4]), unicode_ok), small))
        for evidence in item.get("evidence") or []:
            text = (evidence.get("response") or evidence.get("request") or "")[:900]
            if text:
                blocks.append(Paragraph(_xml(f"Evidence ({evidence.get('kind')}):", unicode_ok), small))
                blocks.append(Paragraph(_xml(text, unicode_ok), pre))
        blocks.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0"), spaceBefore=4))
        story.append(KeepTogether(blocks))

    # ------------------------------------------------------------ methodology
    story.append(PageBreak())
    story.append(Paragraph(_xml("Methodology & honesty rules · المنهجية وقواعد الصدق", unicode_ok), h2))
    for item in data["methodology"]:
        story.append(Paragraph("• " + _xml(item, unicode_ok), base))
    story.append(Paragraph(_xml("Limitations · الحدود", unicode_ok), h2))
    for item in data["limitations"]:
        story.append(Paragraph("• " + _xml(item, unicode_ok), base))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    log.info("PDF report written: %s", path.name)
