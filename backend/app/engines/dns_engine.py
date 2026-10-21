"""DNS engine — real resolution, mail-security analysis and subdomain discovery.

Sources:
* authoritative answers through the system resolver (dnspython),
* Certificate Transparency logs (crt.sh) as a passive discovery source,
* a bounded built-in wordlist (no external wordlist download, no brute force abuse).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from ..core.netguard import authorize_target
from ..core.utils import normalize_host
from ..services.assets import record_change, upsert_asset
from .base import ENGINE_NAME, ENGINE_VERSION, EngineContext, EngineResult

log = logging.getLogger("nexus.engine.dns")

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

# A small, high-signal wordlist — real discovery without hammering a domain.
COMMON_SUBDOMAINS = (
    "www api app admin portal mail smtp imap pop3 webmail vpn remote cdn static assets img images media files "
    "dev test staging stage uat qa sandbox demo beta alpha preprod prod production app1 app2 api1 api2 gateway "
    "auth login sso id identity account accounts billing payments pay invoice shop store cart blog news docs wiki "
    "help support status monitor metrics grafana kibana jenkins git gitlab github bitbucket ci cd build deploy "
    "docker registry k8s kubernetes internal intranet extranet partner partners vendor ftp sftp backup backups db "
    "database mysql postgres redis mongo elastic search analytics data warehouse etl crm erp hr jobs careers "
    "autodiscover autoconfig mx mx1 mx2 ns1 ns2 dns dns1 dns2 proxy lb loadbalancer edge origin cache chat meet "
    "conference video call sip voip pbx printer iot device devices mobile m appstore play upload downloads"
).split()

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "zoho", "cm")


def _resolver() -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 8.0
    resolver.retry_servfail = False
    return resolver


async def _query(resolver: dns.asyncresolver.Resolver, name: str, rdtype: str) -> list[str]:
    try:
        answer = await resolver.resolve(name, rdtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
        return []
    except Exception as exc:  # pragma: no cover - resolver quirks
        log.debug("DNS %s %s failed: %s", rdtype, name, exc)
        return []
    if answer.rrset is None:
        return []
    values: list[str] = []
    for record in answer.rrset:
        text = record.to_text().strip().strip('"')
        if text and text not in values:
            values.append(text)
    return values


# ---------------------------------------------------------------------------
# Mail security (SPF / DMARC / DKIM)
# ---------------------------------------------------------------------------
def analyze_spf(txt_records: list[str]) -> dict[str, Any]:
    spf = next((t for t in txt_records if t.lower().startswith("v=spf1")), "")
    if not spf:
        return {"present": False}
    lowered = spf.lower()
    lookups = sum(lowered.count(token) for token in ("include:", "a:", "a ", "mx", "ptr", "exists:", "redirect="))
    return {
        "present": True,
        "raw": spf,
        "lookups": lookups,
        "too_many_lookups": lookups > 10,
        "all_qualifier": "-all"
        if "-all" in lowered
        else ("~all" if "~all" in lowered else ("?all" if "?all" in lowered else ("+all" if "+all" in lowered else "missing"))),
        "permissive": "+all" in lowered or "?all" in lowered or "all" not in lowered,
    }


def analyze_dmarc(records: list[str]) -> dict[str, Any]:
    dmarc = next((t for t in records if t.lower().startswith("v=dmarc1")), "")
    if not dmarc:
        return {"present": False}
    lowered = dmarc.lower()
    policy = "none"
    for candidate in ("reject", "quarantine", "none"):
        if f"p={candidate}" in lowered:
            policy = candidate
            break
    return {
        "present": True,
        "raw": dmarc,
        "policy": policy,
        "has_rua": "rua=" in lowered,
        "pct": "pct=100" in lowered,
    }


# ---------------------------------------------------------------------------
# Certificate Transparency (passive discovery)
# ---------------------------------------------------------------------------
async def fetch_ct_subdomains(domain: str, *, timeout: float = 25.0, max_names: int = 400) -> tuple[list[str], str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    names: set[str] = set()
    try:
        async with httpx.AsyncClient(timeout=timeout, trust_env=False, follow_redirects=True) as client:
            response = await client.get(url, headers={"User-Agent": "NexusCyberDefense/0.1 (passive CT lookup)"})
            if response.status_code != 200:
                return [], f"crt.sh returned HTTP {response.status_code}"
            payload = response.json()
    except Exception as exc:
        return [], f"crt.sh lookup failed: {type(exc).__name__}"

    for entry in payload if isinstance(payload, list) else []:
        raw = str(entry.get("name_value", "")) + "\n" + str(entry.get("common_name", ""))
        for candidate in raw.splitlines():
            candidate = normalize_host(candidate.strip().lstrip("*."))
            if not candidate or candidate.startswith("@"):
                continue
            if candidate == domain or candidate.endswith("." + domain):
                names.add(candidate)
            if len(names) >= max_names:
                break
    return sorted(names), ""


# ---------------------------------------------------------------------------
# Subdomain enumeration
# ---------------------------------------------------------------------------
async def enumerate_subdomains(
    ctx: EngineContext,
    domain: str,
    *,
    wordlist: list[str],
    concurrency: int = 24,
    use_ct: bool = True,
) -> tuple[list[str], dict[str, Any]]:
    resolver = _resolver()
    found: set[str] = set()
    meta: dict[str, Any] = {"ct_names": 0, "wordlist_hits": 0, "wildcard": False}

    # Wildcard detection so we never report bogus subdomains.
    probe = f"nexus-wildcard-probe-{'x' * 8}.{domain}"
    wildcard_answers = await _query(resolver, probe, "A")
    meta["wildcard"] = bool(wildcard_answers)
    if wildcard_answers:
        ctx.emit(
            f"Wildcard DNS detected for {domain} (any name resolves) — wordlist hits will be marked as unverified.",
            level="warn",
            phase="wordlist",
        )

    semaphore = asyncio.Semaphore(concurrency)

    async def probe_name(name: str) -> tuple[str, list[str]]:
        async with semaphore:
            ctx.check_cancel()
            answers = await _query(resolver, name, "A")
            if not answers:
                answers = await _query(resolver, name, "AAAA")
            await asyncio.sleep(0.02)
            return name, answers

    if use_ct:
        ct_names, ct_error = await fetch_ct_subdomains(domain)
        if ct_error:
            ctx.emit(f"Certificate Transparency source unavailable: {ct_error}", level="warn", phase="ct")
        meta["ct_names"] = len(ct_names)
        for name in ct_names[:200]:
            found.add(name)
        if ct_names:
            ctx.emit(f"Certificate Transparency returned {len(ct_names)} name(s) for {domain}.", phase="ct")

    ctx.phase("wordlist", "running", progress=10)
    tasks = [probe_name(f"{word}.{domain}") for word in wordlist]
    results = await ctx.gather(tasks)
    hits = 0
    for name, answers in results:
        if answers:
            hits += 1
            found.add(name)
    meta["wordlist_hits"] = hits
    ctx.emit(
        f"Wordlist enumeration finished: {hits} additional name(s) responded out of {len(wordlist)} candidates.",
        phase="wordlist",
        data={"hits": hits, "candidates": len(wordlist)},
    )
    ctx.phase("wordlist", "done", progress=100)
    return sorted(found), meta


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
async def run(ctx: EngineContext, targets: list[dict[str, Any]]) -> EngineResult:
    result = EngineResult(data={"targets": []})
    resolver = _resolver()

    for target in targets:
        ctx.check_cancel()
        host = normalize_host(target.get("host") or target.get("value") or "")
        if not host:
            continue

        decision = authorize_target(ctx.db, ctx.project.id, host, require_active=False)
        if not decision.allowed:
            ctx.emit(f"Target skipped — {decision.reason}: {decision.detail}", level="warn", phase="scope_check")
            continue
        ctx.emit(f"Authorized target {host} (scope: {decision.scope_value}).", phase="scope_check")

        target_report: dict[str, Any] = {"host": host, "records": {}, "findings": 0}

        # ---------------------------------------------------------------- records
        ctx.phase("dns", "running", progress=5)
        records: dict[str, list[str]] = {}
        for rdtype in RECORD_TYPES:
            values = await ctx.run_limited(_query, resolver, host, rdtype)
            if values:
                records[rdtype] = values
            await asyncio.sleep(0.02)
        target_report["records"] = records
        ctx.emit(
            f"Collected DNS records: {', '.join(f'{k}({len(v)})' for k, v in records.items()) or 'none'}.",
            phase="dns",
            data={"records": {k: v[:8] for k, v in records.items()}},
        )
        ctx.phase("dns", "done", progress=100)

        # ------------------------------------------------------------ asset store
        scope_id = decision.scope_id
        root_asset, root_created = upsert_asset(
            ctx.db,
            project_id=ctx.project.id,
            asset_type="domain" if host.count(".") <= 1 else "subdomain",
            value=host,
            scope_id=scope_id,
            source="discovery",
            scan_id=ctx.scan.id,
            meta={"dns": {k: v[:10] for k, v in records.items()}},
        )
        if root_created:
            result.assets += 1
        ctx.db.commit()

        # IP assets + relations
        for ip in (records.get("A", []) + records.get("AAAA", [])):
            ip_asset, ip_created = upsert_asset(
                ctx.db,
                project_id=ctx.project.id,
                asset_type="ip",
                value=ip,
                scope_id=scope_id,
                parent_id=root_asset.id,
                source="discovery",
                scan_id=ctx.scan.id,
            )
            if ip_created:
                result.assets += 1
                record_change(
                    ctx.db,
                    project_id=ctx.project.id,
                    asset_id=ip_asset.id,
                    scan_id=ctx.scan.id,
                    kind="new_asset",
                    severity="info",
                    summary=f"New IP address {ip} discovered for {host}",
                )
        ctx.db.commit()

        # ---------------------------------------------------------- mail security
        ctx.phase("mail_security", "running", progress=20)
        txt_records = records.get("TXT", [])
        spf = analyze_spf(txt_records)
        dmarc_records = await ctx.run_limited(_query, resolver, f"_dmarc.{host}", "TXT")
        dmarc = analyze_dmarc(dmarc_records)

        dkim_found: list[str] = []
        for selector in DKIM_SELECTORS:
            values = await ctx.run_limited(_query, resolver, f"{selector}._domainkey.{host}", "TXT")
            if values:
                dkim_found.append(selector)
            await asyncio.sleep(0.02)

        target_report["mail"] = {"spf": spf, "dmarc": dmarc, "dkim_selectors": dkim_found}

        if not spf.get("present"):
            ctx.save(
                check_id="dns_spf_missing",
                category="dns",
                title="No SPF record — domain can be spoofed in email",
                severity="medium",
                confidence="certain",
                target=host,
                location="TXT",
                description="The domain publishes no SPF policy, so receiving servers have no instruction about which hosts may send mail for it.",
                impact="Attackers can send spoofed email that passes basic sender checks, enabling phishing and brand abuse.",
                remediation="Publish an SPF record listing your authorized senders and end it with -all, for example: v=spf1 include:_spf.yourprovider.com -all",
                references=["https://datatracker.ietf.org/doc/html/rfc7208", "https://www.cisa.gov/resources-tools/services/email-security"],
                cwe="CWE-290",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=root_asset.id,
                evidence={
                    "kind": "dns_record",
                    "label": f"TXT records for {host}",
                    "response": "\n".join(txt_records) or "(no TXT records)",
                    "source": "dns",
                },
                tags=["email", "spf"],
            )
            result.findings += 1
        else:
            if spf.get("permissive"):
                ctx.save(
                    check_id="dns_spf_permissive",
                    category="dns",
                    title="Permissive SPF policy (+all / missing all)",
                    severity="high",
                    confidence="certain",
                    target=host,
                    location="TXT",
                    description=f"The SPF policy is permissive: {spf.get('raw')}",
                    impact="Anyone can send mail claiming to be this domain, defeating the purpose of SPF.",
                    remediation="Replace +all/?all with -all after listing every legitimate sender.",
                    references=["https://datatracker.ietf.org/doc/html/rfc7208#section-5.1"],
                    cwe="CWE-290",
                    detected_by=ENGINE_NAME,
                    engine_version=ENGINE_VERSION,
                    asset_id=root_asset.id,
                    evidence={"kind": "dns_record", "label": "SPF record", "response": str(spf.get("raw", "")), "source": "dns"},
                    tags=["email", "spf"],
                )
                result.findings += 1
            if spf.get("too_many_lookups"):
                ctx.save(
                    check_id="dns_spf_lookup_limit",
                    category="dns",
                    title="SPF exceeds the 10 DNS lookup limit",
                    severity="low",
                    confidence="firm",
                    target=host,
                    location="TXT",
                    description=f"SPF requires ~{spf.get('lookups')} DNS lookups, above the RFC 7208 limit of 10.",
                    impact="Receivers may return PermError, which breaks legitimate mail and weakens policy enforcement.",
                    remediation="Flatten or consolidate SPF includes to stay within 10 lookups.",
                    references=["https://datatracker.ietf.org/doc/html/rfc7208#section-4.6.4"],
                    detected_by=ENGINE_NAME,
                    engine_version=ENGINE_VERSION,
                    asset_id=root_asset.id,
                    tags=["email", "spf"],
                )
                result.findings += 1

        if not dmarc.get("present"):
            ctx.save(
                check_id="dns_dmarc_missing",
                category="dns",
                title="No DMARC record — no enforcement or reporting for spoofed mail",
                severity="medium",
                confidence="certain",
                target=host,
                location="_dmarc.TXT",
                description="The domain has no DMARC policy, so receivers cannot be told to quarantine or reject failing mail, and no aggregate reports are produced.",
                impact="Phishing with the organization's domain is far more likely to reach inboxes.",
                remediation="Publish a DMARC record, starting in monitoring then enforcing: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain; then move to p=quarantine and p=reject.",
                references=["https://datatracker.ietf.org/doc/html/rfc7489", "https://www.cisa.gov/resources-tools/services/dmarc"],
                cwe="CWE-290",
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=root_asset.id,
                evidence={"kind": "dns_record", "label": "_dmarc TXT", "response": "(no record)", "source": "dns"},
                tags=["email", "dmarc"],
            )
            result.findings += 1
        elif dmarc.get("policy") == "none" and dmarc.get("pct"):
            ctx.save(
                check_id="dns_dmarc_policy_none",
                category="dns",
                title="DMARC policy is set to p=none (monitoring only)",
                severity="low",
                confidence="certain",
                target=host,
                location="_dmarc.TXT",
                description=f"DMARC exists but does not enforce: {dmarc.get('raw')}",
                impact="Spoofed mail is still delivered; only reports are generated.",
                remediation="Move the policy to p=quarantine and then p=reject once legitimate senders are aligned.",
                references=["https://datatracker.ietf.org/doc/html/rfc7489#section-6.3"],
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=root_asset.id,
                tags=["email", "dmarc"],
            )
            result.findings += 1

        ctx.phase("mail_security", "done", progress=100)

        # -------------------------------------------------------------- hygiene
        ctx.phase("hygiene", "running", progress=20)
        if not records.get("CAA"):
            ctx.save(
                check_id="dns_caa_missing",
                category="dns",
                title="No CAA record — any CA may issue certificates for this domain",
                severity="info",
                confidence="certain",
                target=host,
                location="CAA",
                description="Certificate Authority Authorization is not configured.",
                impact="A mis-issuing CA could create a trusted certificate for the domain without restriction.",
                remediation='Add a CAA record restricting issuance, e.g. example.com. CAA 0 issue "letsencrypt.org"',
                references=["https://datatracker.ietf.org/doc/html/rfc8659"],
                detected_by=ENGINE_NAME,
                engine_version=ENGINE_VERSION,
                asset_id=root_asset.id,
                tags=["dns", "pki"],
            )
            result.findings += 1

        if ctx.require_active:
            ns_records = records.get("NS", [])
            for ns in ns_records[:3]:
                ns_host = ns.rstrip(".").lower()
                try:
                    await _axfr(resolver, ns_host, host)
                    ctx.save(
                        check_id="dns_axfr_allowed",
                        category="dns",
                        title=f"DNS zone transfer (AXFR) allowed on {ns_host}",
                        severity="high",
                        confidence="certain",
                        target=host,
                        location=ns_host,
                        description="The nameserver allowed a full zone transfer to an unauthorized client, exposing every record in the zone.",
                        impact="Attackers enumerate all hosts, internal names and mail routing without touching a single system.",
                        remediation="Restrict AXFR to authorized secondary nameservers only (allow-transfer / TSIG).",
                        references=["https://www.cisa.gov/news-events/alerts"],
                        cwe="CWE-200",
                        detected_by=ENGINE_NAME,
                        engine_version=ENGINE_VERSION,
                        asset_id=root_asset.id,
                        active_check=True,
                        verified=True,
                        tags=["dns", "axfr"],
                    )
                    result.findings += 1
                except Exception:
                    pass
        ctx.phase("hygiene", "done", progress=100)

        # ------------------------------------------------- subdomain enumeration
        if host.count(".") <= 1 or target.get("enumerate_children"):
            ctx.phase("ct", "running", progress=30)
            subdomains, enum_meta = await enumerate_subdomains(
                ctx, host, wordlist=list(COMMON_SUBDOMAINS), use_ct=True
            )
            ctx.phase("ct", "done", progress=100)
            target_report["subdomains"] = subdomains
            target_report["enumeration"] = enum_meta

            for name in subdomains:
                if name == host:
                    continue
                child_decision = authorize_target(ctx.db, ctx.project.id, name, require_active=False)
                if not child_decision.allowed:
                    continue
                child, created = upsert_asset(
                    ctx.db,
                    project_id=ctx.project.id,
                    asset_type="subdomain",
                    value=name,
                    scope_id=child_decision.scope_id,
                    parent_id=root_asset.id,
                    source="discovery",
                    scan_id=ctx.scan.id,
                    meta={"discovery": "ct_and_wordlist"},
                    tags=["discovered"],
                )
                if created:
                    result.assets += 1
                    record_change(
                        ctx.db,
                        project_id=ctx.project.id,
                        asset_id=child.id,
                        scan_id=ctx.scan.id,
                        kind="new_asset",
                        severity="info",
                        summary=f"New subdomain discovered: {name}",
                    )
            ctx.db.commit()

        result.data["targets"].append(target_report)

    # Mark discovery complete in the scan stats
    ctx.scan.stats = {**(ctx.scan.stats or {}), "dns": result.data}
    ctx.db.commit()
    return result


async def _axfr(resolver: dns.asyncresolver.Resolver, ns_host: str, domain: str):
    """Attempt an AXFR against an authoritative nameserver (authorized profiles only)."""
    import dns.query
    import dns.zone

    def _do_transfer():
        return dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=8, lifetime=15))

    return await asyncio.get_running_loop().run_in_executor(None, _do_transfer)
