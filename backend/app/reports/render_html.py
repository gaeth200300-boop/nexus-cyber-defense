"""Self-contained bilingual HTML report (prints well, opens offline)."""

from __future__ import annotations

import html
from typing import Any

from ..core.constants import FINDING_CATEGORIES, SEVERITY_COLORS, SEVERITY_LABELS

CATEGORY_LABELS = {key: value for key, value in FINDING_CATEGORIES.items()}


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _sev_chip(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#64748b")
    label = SEVERITY_LABELS.get(severity, {}).get("en", severity)
    ar = SEVERITY_LABELS.get(severity, {}).get("ar", severity)
    return f'<span class="chip" style="background:{color}1a;color:{color};border:1px solid {color}55">{esc(label)} · {esc(ar)}</span>'


def _ar(text: str) -> str:
    return f'<span dir="rtl" lang="ar">{esc(text)}</span>'


CSS = """
:root { --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --bg:#ffffff; --soft:#f8fafc; --violet:#7c3aed; --cyan:#06b6d4; }
* { box-sizing: border-box; }
body { font-family: "Segoe UI", Tahoma, Arial, sans-serif; color: var(--ink); background: var(--bg); margin: 0; padding: 32px 40px; font-size: 13.5px; line-height: 1.65; }
h1,h2,h3 { line-height: 1.3; margin: 0 0 8px; }
h1 { font-size: 26px; }
h2 { font-size: 18px; margin-top: 34px; padding-bottom: 6px; border-bottom: 2px solid var(--violet); }
h3 { font-size: 15px; margin-top: 22px; }
.banner { background: linear-gradient(120deg,#0b1020,#1e1b4b 55%,#164e63); color:#e2e8f0; padding: 26px 30px; border-radius: 14px; }
.banner .brand { letter-spacing: .22em; font-size: 11px; color:#a5b4fc; text-transform: uppercase; }
.banner h1 { color:#fff; margin: 6px 0; }
.banner .meta { color:#94a3b8; font-size: 12px; }
.classification { display:inline-block; margin-top:12px; padding:4px 10px; border:1px solid #f43f5e88; color:#fda4af; border-radius:999px; font-size:11px; letter-spacing:.08em; }
.grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 14px 0; }
.stat { background: var(--soft); border:1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.stat .n { font-size: 24px; font-weight: 700; }
.stat .l { color: var(--muted); font-size: 11.5px; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; }
th, td { border: 1px solid var(--line); padding: 7px 9px; text-align: left; vertical-align: top; }
th { background: var(--soft); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
.chip { display:inline-block; padding:2px 9px; border-radius:999px; font-size:11.5px; font-weight:600; }
.mono { font-family: Consolas, "Courier New", monospace; font-size: 12px; }
pre { background:#0b1020; color:#e2e8f0; border-radius: 9px; padding: 11px 13px; overflow-x: auto; font-size: 11.5px; white-space: pre-wrap; word-break: break-word; }
.finding { border:1px solid var(--line); border-radius: 12px; padding: 16px 18px; margin: 16px 0; page-break-inside: avoid; }
.finding .head { display:flex; justify-content:space-between; gap: 12px; align-items:flex-start; }
.meta { color: var(--muted); font-size: 12px; }
.note { background:#fffbeb; border:1px solid #fde68a; border-radius: 9px; padding: 10px 13px; font-size: 12.5px; }
.block { margin: 8px 0 4px; }
.block b { display:block; font-size: 11.5px; text-transform: uppercase; letter-spacing:.05em; color: var(--muted); }
ul { margin: 6px 0 6px 20px; }
footer { margin-top: 40px; border-top: 1px solid var(--line); padding-top: 12px; color: var(--muted); font-size: 11.5px; }
@media print { body { padding: 10mm 12mm; } .banner { border-radius: 0; } .finding { break-inside: avoid; } }
"""


def _severity_table(counts: dict[str, int], total_label: str) -> str:
    rows = []
    for severity in ("critical", "high", "medium", "low", "info"):
        color = SEVERITY_COLORS.get(severity, "#64748b")
        rows.append(
            f'<tr><td><span class="chip" style="background:{color}1a;color:{color};border:1px solid {color}55">'
            f'{esc(SEVERITY_LABELS[severity]["en"])} · {esc(SEVERITY_LABELS[severity]["ar"])}</span></td>'
            f'<td style="font-weight:700">{int(counts.get(severity, 0))}</td></tr>'
        )
    rows.append(f'<tr><td><b>{esc(total_label)}</b></td><td><b>{sum(int(v) for v in counts.values())}</b></td></tr>')
    return "<table>" + "".join(rows) + "</table>"


def _finding_card(item: dict[str, Any], index: int) -> str:
    intel_html = ""
    if item.get("intel"):
        chips = []
        for link in item["intel"]:
            tag = "exact" if link.get("match_type") == "exact" else "inferred"
            kev = " · CISA KEV" if link.get("kev") else ""
            chips.append(f'<span class="chip mono" style="background:#eef2ff;color:#4338ca;border:1px solid #c7d2fe">{esc(link["cve"])} ({tag}){esc(kev)}</span>')
        intel_html = f'<div class="block"><b>Intel · استخبارات</b>{" ".join(chips)}</div>'

    evidence_html = ""
    for ev in item.get("evidence") or []:
        evidence_html += (
            f'<div class="block"><b>Evidence · دليل ({esc(ev.get("kind", ""))}'
            + (f' · {ev.get("redactions", 0)} redaction(s)' if ev.get("redactions") else "")
            + f')</b>'
            + (f'<pre>{esc(ev.get("request", ""))}</pre>' if ev.get("request") else "")
            + (f'<pre>{esc(ev.get("response", ""))}</pre>' if ev.get("response") else "")
            + "</div>"
        )

    remediation_html = ""
    if item.get("remediation"):
        remediation_html = (
            f'<div class="block"><b>Remediation · الإصلاح</b><div>{esc(item["remediation"])}</div></div>'
        )

    refs = ""
    if item.get("references"):
        refs = '<div class="block"><b>References · مراجع</b><ul>' + "".join(
            f'<li class="mono">{esc(r)}</li>' for r in item["references"]
        ) + "</ul></div>"

    cvss = f' · CVSS {item["cvss_score"]}' if item.get("cvss_score") is not None else ""
    verified = " · verified" if item.get("verified") else ""
    active = " · active check" if item.get("active_check") else ""
    cwe = f' · {esc(item["cwe"])}' if item.get("cwe") else ""
    cve = f' · {esc(item["cve"])}' if item.get("cve") else ""
    owasp = f' · {esc(item["owasp"])}' if item.get("owasp") else ""
    category = CATEGORY_LABELS.get(item.get("category", ""), {})
    category_label = f'{category.get("en", item.get("category", ""))} · {category.get("ar", "")}'

    return f"""
<div class="finding">
  <div class="head">
    <div>
      <h3>{index}. {esc(item["title"])}</h3>
      <div class="meta">
        {_sev_chip(item["severity"])}
        <span class="chip" style="background:#f1f5f9;color:#334155;border:1px solid #cbd5e1">confidence: {esc(item["confidence"])}{esc(verified)}{esc(active)}</span>
        <span class="chip" style="background:#ecfeff;color:#0e7490;border:1px solid #a5f3fc">status: {esc(item["status"])}</span>
      </div>
    </div>
  </div>
  <table>
    <tr><th style="width:130px">Category · التصنيف</th><td>{esc(category_label)}</td></tr>
    <tr><th>Target · الهدف</th><td class="mono">{esc(item["target"])}{(" · " + esc(item["location"])) if item.get("location") else ""}</td></tr>
    <tr><th>Detection · الكشف</th><td class="mono">{esc(item["detected_by"])} {esc(item["engine_version"])}{esc(cvss)}{esc(cwe)}{esc(cve)}{esc(owasp)}</td></tr>
    <tr><th>Timeline · التوقيت</th><td class="mono">first seen {esc(item["first_seen_at"])} · last seen {esc(item["last_seen_at"])} · occurrences {int(item["occurrence_count"])}</td></tr>
  </table>
  <div class="block"><b>Description · الوصف</b><div>{esc(item["description"])}</div></div>
  <div class="block"><b>Impact · الأثر</b><div>{esc(item["impact"])}</div></div>
  {remediation_html}
  {intel_html}
  {refs}
  {evidence_html}
</div>"""


def render_html(data: dict[str, Any]) -> str:
    summary = data["summary"]
    report = data["report"]
    project = data["project"]
    options = report.get("options") or {}
    lang = options.get("lang", "both")

    def t(en: str, ar: str) -> str:
        if lang == "en":
            return esc(en)
        if lang == "ar":
            return _ar(ar)
        return f"{esc(en)} · {_ar(ar)}"

    findings_html = "".join(_finding_card(item, i + 1) for i, item in enumerate(data["findings"])) or (
        '<div class="note">No findings matched this report\'s filters.</div>'
    )

    scope_rows = "".join(
        f"<tr><td class='mono'>{esc(s['kind'])}</td><td class='mono'>{esc(s['value'])}</td>"
        f"<td>{'yes' if s['include_subdomains'] else 'no'}</td><td>{'yes' if s['allow_active'] else 'no'}</td>"
        f"<td class='mono'>{esc(s['authorization_ref'] or '—')}</td><td class='mono'>{esc(s['authorized_by'] or '—')}</td>"
        f"<td class='mono'>{esc(s['verified_method'])}{(' · ' + esc(s['verified_at'][:10])) if s.get('verified_at') else ''}</td></tr>"
        for s in data["scopes"]
    ) or "<tr><td colspan='7'>No active scope entries.</td></tr>"

    scan_rows = "".join(
        f"<tr><td class='mono'>{esc(s['name'])}</td><td class='mono'>{esc(s['kind'])} / {esc(s['profile'])}</td>"
        f"<td>{esc(s['status'])} ({int(s['progress'])}%)</td><td class='mono'>{esc(s['engine'])} {esc(s['engine_version'])}</td>"
        f"<td class='mono'>{esc((s['started_at'] or '')[:19])} → {esc((s['finished_at'] or '')[:19])}</td>"
        f"<td class='mono'>{esc(', '.join(str(x) for x in s['targets'][:6]))}</td></tr>"
        for s in data["scans"]
    )
    scans_section = (
        f"<h2>{t('Scans included', 'الفحوصات المشمولة')}</h2><table><tr><th>Name</th><th>Kind / profile</th><th>Status</th><th>Engine</th><th>Window</th><th>Targets</th></tr>{scan_rows}</table>"
        if scan_rows
        else ""
    )

    comparison_section = ""
    if data.get("comparison"):
        comp = data["comparison"]
        if comp.get("error"):
            comparison_section = f"<h2>{t('Comparison', 'المقارنة')}</h2><div class='note'>{esc('; '.join(comp['error']))}</div>"
        else:
            comparison_section = (
                f"<h2>{t('Comparison', 'المقارنة')}</h2>"
                f"<div class='grid'>"
                f"<div class='stat'><div class='n' style='color:#f43f5e'>{comp['counts']['new']}</div><div class='l'>{t('New findings', 'نتائج جديدة')}</div></div>"
                f"<div class='stat'><div class='n' style='color:#10b981'>{comp['counts']['resolved']}</div><div class='l'>{t('Resolved', 'معالَجة')}</div></div>"
                f"<div class='stat'><div class='n' style='color:#f59e0b'>{comp['counts']['persistent']}</div><div class='l'>{t('Persistent', 'مستمرة')}</div></div>"
                f"</div>"
                + "<div class='block'><b>New</b><ul>" + "".join(f"<li>{esc(x)}</li>" for x in comp['detail']['new']) + "</ul></div>"
                + "<div class='block'><b>Resolved</b><ul>" + "".join(f"<li>{esc(x)}</li>" for x in comp['detail']['resolved']) + "</ul></div>"
            )

    methodology = "".join(f"<li>{esc(m)}</li>" for m in data["methodology"])
    limitations = "".join(f"<li>{esc(m)}</li>" for m in data["limitations"])

    language_note = ""
    if lang in ("ar", "both"):
        language_note = (
            '<div class="note">Technical finding text is shown in English exactly as produced by the engines; '
            "section headings and labels are bilingual. · النصوص التقنية للنتائج تظهر بالإنجليزية كما أنتجتها المحركات، والعناوين ثنائية اللغة.</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(report["title"])}</title>
<style>{CSS}</style>
</head>
<body>
<div class="banner">
  <div class="brand">NEXUS CYBER DEFENSE · نيكسوس للدفاع السيبراني</div>
  <h1>{t(report["title"], report["title"])}</h1>
  <div class="meta">{t("Project", "المشروع")}: <b>{esc(project["name"])}</b> · {esc(report["kind"])} report v{int(report["version"])} · generated {esc(report["generated_at"])} · platform v{esc(data["platform"]["version"])}</div>
  <div class="classification">{esc(data["platform"]["classification"])}</div>
</div>

<h2>{t("Executive summary", "الملخص التنفيذي")}</h2>
{language_note}
<div class="grid">
  <div class="stat"><div class="n">{int(summary["findings_in_report"])}</div><div class="l">{t("Findings in report", "نتائج في التقرير")}</div></div>
  <div class="stat"><div class="n" style="color:#f43f5e">{int(summary["critical_high"])}</div><div class="l">{t("Critical + High", "حرجة + عالية")}</div></div>
  <div class="stat"><div class="n" style="color:#10b981">{int(summary["verified_findings"])}</div><div class="l">{t("Verified", "مؤكدة")}</div></div>
  <div class="stat"><div class="n">{int(summary["assets"])}</div><div class="l">{t("Assets", "الأصول")}</div></div>
  <div class="stat"><div class="n">{int(summary["services"])}</div><div class="l">{t("Services", "الخدمات")}</div></div>
  <div class="stat"><div class="n">{int(summary["scans"])}</div><div class="l">{t("Scans", "الفحوصات")}</div></div>
</div>
{_severity_table(summary["severity_counts"], "Total · الإجمالي")}

<h2>{t("Scope & authorization", "النطاق والتفويض")}</h2>
<table>
<tr><th>Kind</th><th>Value</th><th>Subdomains</th><th>Active allowed</th><th>Authorization ref</th><th>Authorized by</th><th>Verification</th></tr>
{scope_rows}
</table>
{scans_section}
{comparison_section}

<h2>{t("Findings", "النتائج")} ({len(data["findings"])})</h2>
{findings_html}

<h2>{t("Methodology & honesty rules", "المنهجية وقواعد الصدق")}</h2>
<ul>{methodology}</ul>
<h2>{t("Limitations", "الحدود")}</h2>
<ul>{limitations}</ul>

<footer>
Generated by {esc(data["platform"]["name"])} v{esc(data["platform"]["version"])} · {esc(report["generated_at"])} · report id {esc(report["id"])}
</footer>
</body>
</html>"""
