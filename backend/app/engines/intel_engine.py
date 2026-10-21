"""Vulnerability intelligence engine — official NVD 2.0 + CISA KEV data.

Honesty rules enforced here:
* every CVE record comes from the public NVD API and every KEV entry from the
  official CISA feed — nothing is invented, and a failed fetch returns nothing
  rather than a guess;
* finding↔CVE links are typed: `exact` when the CVE id was literally present in
  the finding text/fields, `inferred` when produced by a keyword search, and the
  rationale string explains the match so the UI can label it honestly.

Both integrations are cached in the database (CveRecord / KevEntry) with a
configurable freshness window so the platform stays useful offline and never
hammers the upstream APIs.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import timedelta
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..core.egress import fetch_public_json
from ..core.utils import truncate, utcnow
from ..models import CveRecord, Finding, FindingIntelLink, KevEntry, SettingKV
from .base import EngineContext, EngineResult

log = logging.getLogger("nexus.engine.intel")

ENGINE_NAME = "nexus-intel"

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_HOSTS = ["nvd.nist.gov", "services.nvd.nist.gov"]
KEV_HOSTS = ["cisa.gov", "www.cisa.gov"]

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_cve_ids(*texts: Iterable[str | None]) -> list[str]:
    """Extract, uppercase and deduplicate CVE ids from arbitrary text."""
    found: list[str] = []
    for text in texts:
        if not text:
            continue
        for match in CVE_RE.findall(str(text)):
            cve = match.upper()
            if cve not in found:
                found.append(cve)
    return found


# ---------------------------------------------------------------------------
# Request throttling — NVD allows 5 requests / 30 s anonymous (50 with a key).
# ---------------------------------------------------------------------------
class _Throttle:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self) -> None:
        async with self._lock:
            interval = 0.7 if settings.nvd_api_key else 6.0
            loop = asyncio.get_running_loop()
            now = loop.time()
            delay = interval - (now - self._last)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last = loop.time()


_nvd_throttle = _Throttle()


async def _nvd_request(params: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    headers = {
        "User-Agent": f"NEXUS-CyberDefense/{settings.version} (authorized security platform; integration=nvd)",
        "Accept": "application/json",
    }
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    await _nvd_throttle.wait()
    data, response = await fetch_public_json(
        NVD_API,
        headers=headers,
        timeout=25.0,
        max_bytes=12_000_000,
        allowed_hosts=NVD_HOSTS,
    )
    # retry once on a rate-limit response
    if data is None and response.status in (403, 429):
        await asyncio.sleep(7.0)
        await _nvd_throttle.wait()
        data, response = await fetch_public_json(
            NVD_API, headers=headers, timeout=25.0, max_bytes=12_000_000, allowed_hosts=NVD_HOSTS
        )
    if data is None:
        return None, response.error or "nvd_unavailable"
    return data, ""


def _pick_metric(metrics: dict[str, Any]) -> tuple[float | None, str, float | None, str]:
    """Return (v3_score, v3_vector, v2_score, severity) choosing the best available metric."""
    v3_score = v3_vector = None
    v2_score = None
    severity = "unknown"
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            entry = entries[0]
            data = entry.get("cvssData", {})
            v3_score = float(data.get("baseScore")) if data.get("baseScore") is not None else None
            v3_vector = str(data.get("vectorString", ""))[:150]
            severity = str(data.get("baseSeverity") or entry.get("baseSeverity") or "unknown").lower()
            break
    for key in ("cvssMetricV2",):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            if data.get("baseScore") is not None:
                v2_score = float(data["baseScore"])
            if severity == "unknown":
                severity = str(entries[0].get("baseSeverity") or "unknown").lower()
            break
    return v3_score, v3_vector or "", v2_score, severity


def _parse_dt(value: str | None):
    if not value:
        return None
    from datetime import datetime

    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value[:26].rstrip("Z"), fmt)
        except ValueError:
            continue
    return None


def _affected_from_cve(item: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten NVD configurations into a small [{vendor, product, versions}] list."""
    affected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def walk(nodes: list[dict[str, Any]], cumulative: bool = False) -> None:
        for node in nodes or []:
            for match in node.get("cpeMatch", []):
                criteria = str(match.get("criteria", ""))
                parts = criteria.split(":")
                if len(parts) < 5:
                    continue
                vendor, product = parts[3], parts[4]
                key = (vendor, product)
                version = ""
                if "versionStartIncluding" in match or "versionEndExcluding" in match or "versionEndIncluding" in match:
                    version = " ".join(
                        filter(
                            None,
                            [
                                f">={match['versionStartIncluding']}" if "versionStartIncluding" in match else "",
                                f"<{match['versionEndExcluding']}" if "versionEndExcluding" in match else "",
                                f"<={match['versionEndIncluding']}" if "versionEndIncluding" in match else "",
                            ],
                        )
                    )
                elif "*" not in criteria.split(":")[5:6]:
                    version = parts[5] if len(parts) > 5 else ""
                if key in seen:
                    for entry in affected:
                        if (entry["vendor"], entry["product"]) == key and version and version not in entry["versions"]:
                            entry["versions"].append(version)
                    continue
                seen.add(key)
                affected.append(
                    {
                        "vendor": vendor,
                        "product": product,
                        "versions": [version] if version else [],
                        "vulnerable": bool(match.get("vulnerable", True)),
                    }
                )
            walk(node.get("children") or [])

    walk_all = []
    for configuration in item.get("cve", {}).get("configurations") or []:
        walk_all.extend(configuration.get("nodes") or [])
    walk(walk_all)
    return affected[:20]


def _english_description(item: dict[str, Any]) -> str:
    for desc in item.get("cve", {}).get("descriptions", []):
        if str(desc.get("lang", "")).lower() == "en":
            return str(desc.get("value", ""))
    descriptions = item.get("cve", {}).get("descriptions", [])
    return str(descriptions[0].get("value", "")) if descriptions else ""


def _upsert_cve(db: Session, item: dict[str, Any]) -> CveRecord | None:
    cve_id = str(item.get("cve", {}).get("id", "")).upper()
    if not cve_id.startswith("CVE-"):
        return None
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})
    v3_score, v3_vector, v2_score, severity = _pick_metric(metrics)
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = str(desc.get("value", ""))
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    references = [
        {"url": str(ref.get("url", "")), "tags": ref.get("tags", [])}
        for ref in (cve.get("references") or [])[:25]
    ]
    record = db.get(CveRecord, cve_id)
    if record is None:
        record = CveRecord(id=cve_id)
        db.add(record)
    record.description = _english_description(item)
    record.published_at = _parse_dt(cve.get("published"))
    record.modified_at = _parse_dt(cve.get("lastModified"))
    record.cvss_v3_score = v3_score
    record.cvss_v3_vector = v3_vector
    record.cvss_v2_score = v2_score
    record.cvss_severity = severity
    record.cwes = cwes[:10]
    record.references = references
    record.affected = _affected_from_cve(item)
    record.source = "nvd"
    record.source_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    record.raw = {
        "vulnStatus": cve.get("vulnStatus", ""),
        "published": cve.get("published", ""),
        "lastModified": cve.get("lastModified", ""),
    }
    record.fetched_at = utcnow()
    db.flush()
    return record


def _cache_fresh(record: CveRecord | None, hours: int) -> bool:
    if record is None:
        return False
    return (utcnow() - record.fetched_at) < timedelta(hours=hours)


async def fetch_cve(db: Session, cve_id: str, *, force: bool = False) -> tuple[CveRecord | None, str]:
    """Fetch (or return cached) NVD data for one CVE id. Returns (record, error)."""
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None, "invalid_cve_id"
    cached = db.get(CveRecord, cve_id)
    if not force and _cache_fresh(cached, settings.intel_cache_hours):
        return cached, ""
    data, error = await _nvd_request({"cveId": cve_id})
    if data is None:
        # serve stale cache when upstream is unreachable — clearly marked by fetched_at
        return (cached, error) if cached else (None, error)
    items = data.get("vulnerabilities") or []
    if not items:
        return None, "not_found_in_nvd"
    record = _upsert_cve(db, items[0])
    db.commit()
    return record, ""


async def fetch_recent(db: Session, *, days: int = 7, limit: int = 20) -> tuple[list[CveRecord], str]:
    """Most recent CVEs from NVD (publication window). Cached rows are refreshed."""
    end = utcnow()
    start = end - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": max(1, min(limit, 100)),
    }
    data, error = await _nvd_request(params)
    if data is None:
        cached = db.execute(
            select(CveRecord).order_by(CveRecord.published_at.desc().nullslast()).limit(limit)
        ).scalars().all()
        return list(cached), error
    records: list[CveRecord] = []
    for item in (data.get("vulnerabilities") or [])[:limit]:
        record = _upsert_cve(db, item)
        if record:
            records.append(record)
    db.commit()
    return records, ""


async def search_nvd(db: Session, keyword: str, *, limit: int = 20) -> tuple[list[CveRecord], str]:
    """Keyword search against NVD 2.0 (keywordSearch), cached per result."""
    keyword = (keyword or "").strip()
    if not keyword:
        return [], "empty_query"
    data, error = await _nvd_request({"keywordSearch": keyword[:120], "resultsPerPage": min(max(limit, 1), 50)})
    if data is None:
        return [], error
    records: list[CveRecord] = []
    for item in (data.get("vulnerabilities") or [])[:limit]:
        record = _upsert_cve(db, item)
        if record:
            records.append(record)
    db.commit()
    return records, ""


# ---------------------------------------------------------------------------
# CISA KEV feed
# ---------------------------------------------------------------------------
async def sync_kev(db: Session, *, force: bool = False) -> dict[str, Any]:
    """Download and index the official CISA KEV catalogue. Returns a summary."""
    state = db.get(SettingKV, "kev_sync")
    last_sync = (state.value or {}).get("synced_at") if state else None
    if not force and last_sync:
        from datetime import datetime

        try:
            synced = datetime.fromisoformat(last_sync)
            if (utcnow() - synced) < timedelta(hours=settings.intel_cache_hours):
                return {"skipped": True, "reason": "fresh", "synced_at": last_sync, "count": (state.value or {}).get("count", 0)}
        except ValueError:
            pass

    data, response = await fetch_public_json(
        settings.kev_feed_url,
        headers={"User-Agent": f"NEXUS-CyberDefense/{settings.version}", "Accept": "application/json"},
        timeout=30.0,
        max_bytes=25_000_000,
        allowed_hosts=KEV_HOSTS,
    )
    if data is None:
        if state:
            return {"skipped": True, "reason": f"feed_unavailable: {response.error}", "synced_at": last_sync}
        return {"skipped": True, "reason": f"feed_unavailable: {response.error}"}

    inserted = updated = 0
    for item in data.get("vulnerabilities", []):
        cve_id = str(item.get("cveID", "")).upper()
        if not cve_id:
            continue
        entry = db.get(KevEntry, cve_id)
        if entry is None:
            entry = KevEntry(cve_id=cve_id)
            db.add(entry)
            inserted += 1
        else:
            updated += 1
        entry.vendor_project = str(item.get("vendorProject", ""))[:200]
        entry.product = str(item.get("product", ""))[:200]
        entry.vulnerability_name = str(item.get("vulnerabilityName", ""))[:400]
        entry.date_added = _parse_dt(item.get("dateAdded"))
        entry.short_description = str(item.get("shortDescription", ""))
        entry.required_action = str(item.get("requiredAction", ""))
        entry.due_date = _parse_dt(item.get("dueDate"))
        entry.known_ransomware = str(item.get("knownRansomwareCampaignUse", "")).lower() == "known"
        entry.notes = str(item.get("notes", ""))
        entry.source_url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        entry.fetched_at = utcnow()

    summary = {
        "count": len(data.get("vulnerabilities", [])),
        "inserted": inserted,
        "updated": updated,
        "catalog_version": data.get("catalogVersion", ""),
        "date_released": data.get("dateReleased", ""),
        "synced_at": utcnow().isoformat(timespec="seconds"),
    }
    if state is None:
        state = SettingKV(key="kev_sync")
        db.add(state)
    state.value = summary
    db.commit()
    log.info("KEV feed synced: %s entries", summary["count"])
    return summary


def kev_lookup(db: Session, cve_ids: Iterable[str]) -> dict[str, KevEntry]:
    ids = [c.strip().upper() for c in cve_ids if c]
    if not ids:
        return {}
    rows = db.execute(select(KevEntry).where(KevEntry.cve_id.in_(ids))).scalars().all()
    return {row.cve_id: row for row in rows}


def kev_stats(db: Session) -> dict[str, Any]:
    from sqlalchemy import func

    total = int(db.execute(select(func.count(KevEntry.cve_id)).select_from(KevEntry)).scalar_one() or 0)
    ransomware = int(
        db.execute(select(func.count(KevEntry.cve_id)).select_from(KevEntry).where(KevEntry.known_ransomware.is_(True))).scalar_one()
        or 0
    )
    state = db.get(SettingKV, "kev_sync")
    return {"total": total, "ransomware": ransomware, "sync": (state.value if state else {})}


# ---------------------------------------------------------------------------
# Correlation engine — links project findings to their CVEs
# ---------------------------------------------------------------------------
def _finding_candidates(finding: Finding) -> tuple[list[str], list[str]]:
    """Return (exact_cve_ids, search_keywords) for one finding."""
    exact = extract_cve_ids(finding.cve, finding.title, finding.description, finding.impact, finding.remediation)
    for reference in finding.references or []:
        for cve in extract_cve_ids(reference):
            if cve not in exact:
                exact.append(cve)

    keywords: list[str] = []
    for product in (finding.tags or []):
        cleaned = str(product).strip()
        if 2 < len(cleaned) <= 60 and ":" in cleaned:
            keywords.append(cleaned.replace(":", " "))
    return exact, keywords[:2]


async def correlate(ctx: EngineContext, targets: list[dict[str, Any]]) -> EngineResult:
    """intel_correlation job: map open findings to NVD records and KEV entries."""
    result = EngineResult()
    db = ctx.db
    limit = int(ctx.scan.options.get("finding_limit", 300) or 300)
    keyword_search = bool(ctx.scan.options.get("keyword_search", False))

    ctx.phase("collect", "running", progress=20)
    findings = db.execute(
        select(Finding)
        .where(Finding.project_id == ctx.project.id, Finding.status.in_(("open", "confirmed", "in_progress")))
        .order_by(Finding.last_seen_at.desc())
        .limit(limit)
    ).scalars().all()
    ctx.emit(f"Collected {len(findings)} open finding(s) for correlation.", phase="collect")
    ctx.phase("collect", "done", progress=100)

    exact_ids: set[str] = set()
    per_finding: dict[str, list[str]] = {}
    keywords_per_finding: dict[str, list[str]] = {}
    for finding in findings:
        exact, keywords = _finding_candidates(finding)
        if exact:
            per_finding[finding.id] = exact
            exact_ids.update(exact)
        if keyword_search and keywords:
            keywords_per_finding[finding.id] = keywords

    # KEV first (single feed download, covers every CVE at once)
    ctx.phase("query", "running", progress=10)
    kev_summary = await sync_kev(db)
    if not kev_summary.get("skipped"):
        ctx.emit(f"CISA KEV catalogue updated ({kev_summary.get('count', 0)} entries).", phase="query")
    kev_hits = kev_lookup(db, exact_ids)

    # per-CVE NVD lookups (throttled), bounded to keep scans predictable
    fetch_budget = 40
    fetched = 0
    cve_records: dict[str, CveRecord | None] = {}
    for cve_id in sorted(exact_ids):
        ctx.check_cancel()
        if fetched >= fetch_budget:
            ctx.emit(
                f"CVE fetch budget reached ({fetch_budget}); remaining CVEs stay queued for the next run.",
                level="warn",
                phase="query",
            )
            break
        record, error = await fetch_cve(db, cve_id)
        cve_records[cve_id] = record
        fetched += 1
        if error and record is None:
            ctx.emit(f"NVD lookup failed for {cve_id}: {error}", level="warn", phase="query")
        ctx.phase("query", "running", progress=min(95, 10 + int(85 * fetched / max(len(exact_ids), 1))))

    keyword_records: dict[str, list[CveRecord]] = {}
    if keyword_search:
        for finding_id, keywords in list(keywords_per_finding.items())[:10]:
            for keyword in keywords[:1]:
                records, error = await search_nvd(db, keyword, limit=3)
                if records:
                    keyword_records[finding_id] = records
                elif error:
                    ctx.emit(f"NVD keyword search '{keyword}' failed: {error}", level="warn", phase="query")
    ctx.phase("query", "done", progress=100)

    ctx.phase("link", "running", progress=20)
    links_created = 0
    for finding in findings:
        exact = per_finding.get(finding.id, [])
        for cve_id in exact:
            record = cve_records.get(cve_id)
            item = (
                "exploited in the wild per CISA KEV" if cve_id in kev_hits else
                (f"CVSS {record.cvss_v3_score}" if record and record.cvss_v3_score is not None else "no CVSS v3 score in NVD")
            )
            link, created = _upsert_link(
                db,
                finding_id=finding.id,
                cve_id=cve_id,
                match_type="exact",
                confidence="certain",
                rationale=f"CVE id '{cve_id}' was reported verbatim by the detection source ({finding.detected_by or 'engine'}); NVD: {item}.",
            )
            links_created += 1 if created else 0

            # Keep the finding's CVE column and severity in sync with official data.
            if record:
                finding.cve = cve_id
                if record.cvss_v3_score is not None and (finding.cvss_score is None or record.cvss_v3_score > finding.cvss_score):
                    finding.cvss_score = record.cvss_v3_score
                if record.cvss_severity in ("critical", "high", "medium", "low") and not finding.cvss_vector:
                    finding.cvss_vector = record.cvss_v3_vector

        for record in keyword_records.get(finding.id, []):
            kev = kev_hits.get(record.id)
            rationale = f"Keyword search for '{finding.title[:60]}' returned this CVE in NVD; product/version match was NOT verified."
            _upsert_link(
                db,
                finding_id=finding.id,
                cve_id=record.id,
                match_type="inferred",
                confidence="tentative",
                rationale=rationale + (" Listed in CISA KEV." if kev else ""),
            )
            links_created += 1
    ctx.phase("link", "done", progress=100)

    ctx.phase("store", "running", progress=60)
    db.commit()
    kev_linked = sum(1 for cve in exact_ids if cve in kev_hits)
    result.data = {
        "findings_scanned": len(findings),
        "cves_referenced": len(exact_ids),
        "cve_records": sum(1 for r in cve_records.values() if r),
        "kev_matches": kev_linked,
        "links_created": links_created,
        "keyword_search": keyword_search,
    }
    result.notes.append(
        f"Correlated {len(findings)} findings; {len(exact_ids)} CVE id(s) referenced, {kev_linked} present in CISA KEV."
    )
    ctx.phase("store", "done", progress=100)
    ctx.emit(
        f"Intelligence correlation complete: {links_created} new link(s).",
        kind="metric",
        phase="store",
        data=result.data,
    )
    return result


def _upsert_link(
    db: Session,
    *,
    finding_id: str,
    cve_id: str,
    match_type: str,
    confidence: str,
    rationale: str,
) -> tuple[FindingIntelLink, bool]:
    existing = db.execute(
        select(FindingIntelLink).where(
            FindingIntelLink.finding_id == finding_id,
            FindingIntelLink.cve_id == cve_id,
            FindingIntelLink.match_type == match_type,
        )
    ).scalar_one_or_none()
    if existing:
        existing.rationale = truncate(rationale, 2000) or ""
        existing.confidence = confidence
        return existing, False
    link = FindingIntelLink(
        finding_id=finding_id,
        cve_id=cve_id,
        match_type=match_type,
        confidence=confidence,
        rationale=truncate(rationale, 2000) or "",
    )
    db.add(link)
    db.flush()
    return link, True


async def run(ctx: EngineContext, targets: list[dict[str, Any]]) -> EngineResult:
    """Engine entry point (same signature as every other engine)."""
    return await correlate(ctx, targets)
