"""Lab verification engine.

Checks are evaluated with the platform's real parsers and against the user's
real project data — a lab is never marked passed because a number was typed in.
Check outcomes are explicit: passed / failed / needs_answers / needs_project /
manual / error, so the UI can always explain *why*.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.utils import utcnow
from ..models import Achievement, Asset, Lab, LabRun, Scan, Scope
from .files import labs_dir

log = logging.getLogger("nexus.labs.verify")


# ---------------------------------------------------------------------------
# Assertion helpers per fixture kind
# ---------------------------------------------------------------------------
def _load_file(name: str) -> Any:
    path = labs_dir() / name
    if not path.exists():
        raise FileNotFoundError(f"lab fixture '{name}' is missing — run: python -m app.cli seed")
    return path


def _parse_header_dump(text: str) -> tuple[dict[str, str], list[str], bool]:
    """Parse the captured-response fixture into (headers, set-cookies, is_https)."""
    lines = [line.rstrip("\r") for line in text.splitlines()]
    header_lines = [l for l in lines if l and not l.startswith("#")]
    is_https = any(l.upper().startswith("HTTPS ") for l in header_lines[:3])
    headers: dict[str, str] = {}
    set_cookies: list[str] = []
    for line in header_lines:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key_l, value_v = key.strip().lower(), value.strip()
        if key_l in ("http/1.1", "https") or " " in key_l and not value_v:
            continue
        if key_l == "set-cookie":
            set_cookies.append(value_v)
        headers[key_l] = value_v
    return headers, set_cookies, is_https


def _checks_logs(path: Any, spec: dict[str, Any]) -> tuple[bool, str]:
    from ..engines.logs_engine import BUILTIN_RULES, detect_format, parse_line, rule_matches

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = [l for l in text.splitlines() if l.strip()][:5000]
    assert_kind = spec.get("assert")

    if assert_kind == "format":
        detected = detect_format(lines[:200])
        expected = str(spec.get("value", "")).lower()
        ok = detected == expected
        return ok, f"detected format '{detected}', expected '{expected}'"

    if assert_kind == "rule_events":
        rule_name = str(spec.get("rule", ""))
        minimum = int(spec.get("min", 1))
        rule = next((r for r in BUILTIN_RULES if r["name"] == rule_name), None)
        if rule is None:
            return False, f"rule '{rule_name}' not found in the engine catalogue"
        detected_format = detect_format(lines[:200])
        matched = 0
        for line in lines:
            event = parse_line(line, detected_format)
            if event and rule_matches(rule["definition"], event):
                matched += 1
        return matched >= minimum, f"rule '{rule_name}' matched {matched} event(s), required >= {minimum}"

    return False, f"unknown logs assertion '{assert_kind}'"


def _checks_pcap(path: Any, spec: dict[str, Any]) -> tuple[bool, str]:
    from ..engines.pcap_engine import analyze_pcap

    summary = analyze_pcap(str(path))
    if summary.get("error"):
        return False, f"capture could not be parsed: {summary['error']}"
    assert_kind = spec.get("assert")
    if assert_kind == "dns_suspicious_min":
        value = len(summary["dns_suspicious"])
        return value >= int(spec.get("value", 1)), f"suspicious DNS queries found: {value}"
    if assert_kind == "credentials_min":
        value = len(summary["credentials"])
        return value >= int(spec.get("value", 1)), f"credential leaks found: {value}"
    if assert_kind == "arp_conflicts_min":
        conflicts = {ip: macs for ip, macs in summary["arp_table"].items() if len(macs) > 1}
        return len(conflicts) >= int(spec.get("value", 1)), f"ARP conflicts found: {len(conflicts)}"
    return False, f"unknown pcap assertion '{assert_kind}'"


def _checks_http(path: Any, spec: dict[str, Any]) -> tuple[bool, str]:
    from ..engines.http_engine import analyze_cookies, analyze_security_headers

    headers, set_cookies, is_https = _parse_header_dump(path.read_text(encoding="utf-8", errors="replace"))
    _, header_issues = analyze_security_headers(headers, is_https=is_https)
    _, cookie_issues = analyze_cookies(set_cookies, is_https=is_https)
    issue_ids = {issue.get("check_id", "") for issue in (header_issues + cookie_issues)}

    assert_kind = spec.get("assert")
    if assert_kind == "issue_check_ids":
        expected = list(spec.get("value", []))
        missing = [e for e in expected if e not in issue_ids]
        return not missing, f"confirmed {len(expected) - len(missing)}/{len(expected)} expected issues" + (f"; missing: {missing}" if missing else "")
    if assert_kind == "issue_min":
        minimum = int(spec.get("value", 1))
        return len(issue_ids) >= minimum, f"analyzer produced {len(issue_ids)} distinct issue(s), required >= {minimum}"
    return False, f"unknown http assertion '{assert_kind}'"


def _checks_tls(path: Any, spec: dict[str, Any]) -> tuple[bool, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    cert = x509.load_pem_x509_certificate(path.read_bytes())
    assert_kind = spec.get("assert")
    if assert_kind == "expired":
        now = utcnow()
        try:
            not_after = cert.not_valid_after_utc.replace(tzinfo=None)
        except AttributeError:  # older cryptography
            not_after = cert.not_valid_after
        return not_after < now, f"notAfter={not_after.isoformat()}"
    if assert_kind == "key_size_lt":
        public = cert.public_key()
        if isinstance(public, rsa.RSAPublicKey):
            size = public.key_size
        elif isinstance(public, ec.EllipticCurvePublicKey):
            size = public.curve.key_size
        else:
            size = 0
        return 0 < size < int(spec.get("value", 2048)), f"key size = {size} bits"
    if assert_kind == "san_count_min":
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            count = len(san.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            count = 0
        return count >= int(spec.get("value", 1)), f"SAN DNS entries = {count}"
    return False, f"unknown tls assertion '{assert_kind}'"


def _checks_project(db: Session, run: LabRun, spec: dict[str, Any]) -> tuple[str, str]:
    """Returns (status, detail) where status can be needs_project."""
    if not run.project_id:
        return "needs_project", "start this lab from a project for automatic validation"
    project_id = run.project_id
    assert_kind = spec.get("assert")

    if assert_kind == "scopes_min":
        count = int(db.execute(select(func.count(Scope.id)).where(Scope.project_id == project_id, Scope.is_active.is_(True))).scalar_one() or 0)
        return ("passed" if count >= int(spec.get("value", 1)) else "failed"), f"active scope entries: {count}"
    if assert_kind == "scan_kind_completed":
        kind = str(spec.get("value", ""))
        count = int(
            db.execute(
                select(func.count(Scan.id)).where(
                    Scan.project_id == project_id, Scan.kind == kind, Scan.status.in_(("completed", "partial"))
                )
            ).scalar_one()
            or 0
        )
        return ("passed" if count >= 1 else "failed"), f"completed '{kind}' scans: {count}"
    if assert_kind == "scans_min":
        count = int(db.execute(select(func.count(Scan.id)).where(Scan.project_id == project_id)).scalar_one() or 0)
        return ("passed" if count >= int(spec.get("value", 1)) else "failed"), f"scans in project: {count}"
    if assert_kind == "assets_min":
        count = int(db.execute(select(func.count(Asset.id)).where(Asset.project_id == project_id)).scalar_one() or 0)
        return ("passed" if count >= int(spec.get("value", 1)) else "failed"), f"assets in project: {count}"
    if assert_kind == "findings_min":
        from ..models import Finding

        count = int(db.execute(select(func.count(Finding.id)).where(Finding.project_id == project_id)).scalar_one() or 0)
        return ("passed" if count >= int(spec.get("value", 1)) else "failed"), f"findings in project: {count}"
    return "error", f"unknown project assertion '{assert_kind}'"


# ---------------------------------------------------------------------------
# Check evaluation
# ---------------------------------------------------------------------------
def _evaluate_check(db: Session, lab: Lab, run: LabRun, check: dict[str, Any]) -> dict[str, Any]:
    key = check.get("key", "")
    kind = check.get("type", "quiz")
    points = int(check.get("points", 0))
    result: dict[str, Any] = {
        "key": key,
        "type": kind,
        "label_en": check.get("label_en", ""),
        "label_ar": check.get("label_ar", ""),
        "points": points,
        "status": "error",
        "detail": "",
        "earned": 0,
    }
    spec = check.get("spec") or {}
    answers = (run.evidence or {}).get("answers") or {}

    try:
        if kind == "quiz":
            given = str(answers.get(key, "")).strip()
            if not given:
                result.update(status="needs_answers", detail="submit an answer to be graded")
            else:
                expected = str(spec.get("answer", ""))
                if given == expected:
                    result.update(status="passed", earned=points, detail="correct")
                else:
                    result.update(status="failed", detail="incorrect answer")
        elif kind == "file_analysis":
            path = _load_file(str(spec.get("file", "")))
            file_kind = str(spec.get("kind", ""))
            if file_kind == "logs":
                ok, detail = _checks_logs(path, spec)
            elif file_kind == "pcap":
                ok, detail = _checks_pcap(path, spec)
            elif file_kind == "http":
                ok, detail = _checks_http(path, spec)
            elif file_kind == "tls":
                ok, detail = _checks_tls(path, spec)
            else:
                ok, detail = False, f"unknown file analysis kind '{file_kind}'"
            result.update(status="passed" if ok else "failed", earned=points if ok else 0, detail=detail)
        elif kind == "project_state":
            status, detail = _checks_project(db, run, spec)
            result.update(status=status, earned=points if status == "passed" else 0, detail=detail)
        elif kind == "manual":
            result.update(status="manual", detail="reviewed by an instructor — not auto-scored")
        else:
            result.update(status="error", detail=f"unknown check type '{kind}'")
    except FileNotFoundError as exc:
        result.update(status="error", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - a broken check must not crash verification
        log.warning("lab check %s failed to evaluate: %s", key, exc)
        result.update(status="error", detail=f"{type(exc).__name__}: {exc}")
    return result


ACHIEVEMENTS: dict[str, dict[str, Any]] = {
    "first_lab": {"en": "First blood — complete your first lab", "ar": "أول إنجاز — أكمل أول مختبر", "points": 10},
    "five_labs": {"en": "Five labs completed", "ar": "أكملت خمسة مختبرات", "points": 50},
    "pcap_hunter": {"en": "PCAP hunter — pass three packet labs", "ar": "صائد الحزم — اجتز ثلاثة مختبرات تحليل حزم", "points": 30},
    "log_analyst": {"en": "Log analyst — pass three log labs", "ar": "محلل سجلات — اجتز ثلاثة مختبرات سجلات", "points": 30},
    "perfect_run": {"en": "Perfect run — full marks on a lab in one attempt", "ar": "أداء كامل — علامة كاملة من المحاولة الأولى", "points": 20},
}


def _grant_achievement(db: Session, user_id: str, code: str) -> bool:
    existing = db.execute(
        select(Achievement).where(Achievement.user_id == user_id, Achievement.code == code)
    ).scalar_one_or_none()
    if existing:
        return False
    meta = ACHIEVEMENTS.get(code, {"en": code, "ar": code, "points": 0})
    db.add(
        Achievement(
            user_id=user_id,
            code=code,
            title_en=meta["en"][:160],
            title_ar=meta["ar"][:160],
            points=int(meta["points"]),
        )
    )
    return True


def _maybe_grant_achievements(db: Session, lab: Lab, run: LabRun, checks: list[dict[str, Any]]) -> list[str]:
    granted: list[str] = []
    passed_all = all(c["status"] in ("passed", "manual") for c in checks)
    if not passed_all:
        return granted

    if _grant_achievement(db, run.user_id, "first_lab"):
        granted.append("first_lab")

    passed_count = int(
        db.execute(
            select(func.count(LabRun.id)).where(LabRun.user_id == run.user_id, LabRun.status == "passed")
        ).scalar_one()
        or 0
    )
    if passed_count >= 5 and _grant_achievement(db, run.user_id, "five_labs"):
        granted.append("five_labs")

    if lab.category == "pcap":
        pcap_passed = int(
            db.execute(
                select(func.count(LabRun.id))
                .select_from(LabRun)
                .join(Lab, Lab.id == LabRun.lab_id)
                .where(LabRun.user_id == run.user_id, LabRun.status == "passed", Lab.category == "pcap")
            ).scalar_one()
            or 0
        )
        if pcap_passed >= 3 and _grant_achievement(db, run.user_id, "pcap_hunter"):
            granted.append("pcap_hunter")
    if lab.category == "logs":
        log_passed = int(
            db.execute(
                select(func.count(LabRun.id))
                .select_from(LabRun)
                .join(Lab, Lab.id == LabRun.lab_id)
                .where(LabRun.user_id == run.user_id, LabRun.status == "passed", Lab.category == "logs")
            ).scalar_one()
            or 0
        )
        if log_passed >= 3 and _grant_achievement(db, run.user_id, "log_analyst"):
            granted.append("log_analyst")
    if run.attempts <= 1 and _grant_achievement(db, run.user_id, "perfect_run"):
        granted.append("perfect_run")
    return granted


async def verify_lab_run(db: Session, run_id: str) -> dict[str, Any]:
    """Grade a lab run. Safe to call repeatedly (idempotent scoring)."""
    run = db.get(LabRun, run_id)
    if run is None:
        raise RuntimeError(f"lab run {run_id} not found")
    lab = db.get(Lab, run.lab_id)
    if lab is None:
        raise RuntimeError(f"lab {run.lab_id} not found")

    checks = list(lab.checks or [])
    results: list[dict[str, Any]] = []
    for check in checks:
        results.append(_evaluate_check(db, lab, run, check))
        await asyncio.sleep(0)  # keep the loop responsive during heavy checks

    auto_checks = [r for r in results if r["status"] != "manual"]
    earned = sum(int(r["earned"]) for r in results)
    max_points = sum(int(r["points"]) for r in auto_checks)
    passed = bool(auto_checks) and all(r["status"] == "passed" for r in auto_checks)
    pending = any(r["status"] in ("needs_answers", "needs_project") for r in results)

    run.checks_result = results
    run.score = earned
    if passed:
        run.status = "passed"
        run.finished_at = run.finished_at or utcnow()
    elif pending:
        run.status = "started"
    else:
        run.status = "failed"
    granted = _maybe_grant_achievements(db, lab, run, results) if passed else []
    db.commit()

    log.info("lab run %s verified: passed=%s score=%s/%s", run.id, passed, earned, max_points)
    return {
        "run_id": run.id,
        "lab_id": lab.id,
        "passed": passed,
        "score": earned,
        "max_points": max_points,
        "checks": results,
        "achievements": granted,
        "pending": pending,
    }
