"""Security posture scoring.

The score is a transparent weighted roll-up of measured facts.  Two rules
govern this module:

1. A factor is only included when its input data actually exists.  If nothing
   has been scanned, there is no "exposure" factor - the factor is listed under
   ``missing_information`` and the remaining weights are re-normalised.
2. The score never rewards an unmeasured area.  ``coverage`` reports how much
   of the model could be evaluated, so a high score with low coverage is
   visibly different from a high score backed by evidence.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.utils import utcnow
from ..models import Alert, Asset, Evidence, Finding, Incident, Scan, Service

log = logging.getLogger("nexus.services.posture")

SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}

# Documented model.  Weights are relative and re-normalised over the factors
# that could actually be measured.
MODEL: list[dict[str, Any]] = [
    {
        "key": "remediation",
        "label_en": "Critical & high finding remediation",
        "label_ar": "معالجة الثغرات الحرجة والعالية",
        "weight": 25,
        "requires": "open findings",
    },
    {
        "key": "exposure",
        "label_en": "Assessment coverage",
        "label_ar": "تغطية الفحص",
        "weight": 20,
        "requires": "assets and scans",
    },
    {
        "key": "scope",
        "label_en": "Authorized scope coverage",
        "label_ar": "تغطية النطاق المصرّح",
        "weight": 15,
        "requires": "assets with scope",
    },
    {
        "key": "detection",
        "label_en": "Detection coverage",
        "label_ar": "تغطية الكشف",
        "weight": 15,
        "requires": "detections or alerts",
    },
    {
        "key": "inventory",
        "label_en": "Inventory freshness",
        "label_ar": "حداثة الجرد",
        "weight": 10,
        "requires": "asset observations",
    },
    {
        "key": "integrity",
        "label_en": "Evidence integrity",
        "label_ar": "سلامة الأدلة",
        "weight": 10,
        "requires": "evidence records",
    },
    {
        "key": "monitoring",
        "label_en": "Asset monitoring",
        "label_ar": "مراقبة الأصول",
        "weight": 5,
        "requires": "monitored assets",
    },
]

FACTOR_LIMIT = 30  # days
STALE_LIMIT = 45  # days before an asset observation counts as stale


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    if score >= 35:
        return "E"
    return "F"


def compute_posture(db: Session, project_id: str) -> dict[str, Any]:
    """Compute the posture score for a project from stored evidence."""
    now = utcnow()
    cutoff = now - timedelta(days=FACTOR_LIMIT)

    assets = db.execute(select(Asset).where(Asset.project_id == project_id)).scalars().all()
    findings = db.execute(select(Finding).where(Finding.project_id == project_id)).scalars().all()
    scans = db.execute(select(Scan).where(Scan.project_id == project_id)).scalars().all()
    alerts = db.execute(select(Alert).where(Alert.project_id == project_id)).scalars().all()
    incidents = db.execute(select(Incident).where(Incident.project_id == project_id)).scalars().all()
    evidence = db.execute(select(Evidence).where(Evidence.project_id == project_id)).scalars().all()
    services = db.execute(select(Service).where(Service.project_id == project_id)).scalars().all()

    open_findings = [item for item in findings if item.status in ("open", "confirmed", "new")]
    recent_scans = [scan for scan in scans if scan.created_at and scan.created_at >= cutoff]
    completed_scans = [scan for scan in scans if scan.status == "completed"]

    factors: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []

    def factor(key: str, earned: float, maximum: float, detail: str, action: str = "") -> None:
        spec = next(item for item in MODEL if item["key"] == key)
        factors.append(
            {
                "key": key,
                "label_en": spec["label_en"],
                "label_ar": spec["label_ar"],
                "weight": spec["weight"],
                "earned": round(earned, 2),
                "max": round(maximum, 2),
                "percent": round((earned / maximum) * 100, 1) if maximum else 0.0,
                "detail": detail,
            }
        )
        if action:
            actions.append({"key": key, "action": action})

    def absent(key: str, reason: str) -> None:
        spec = next(item for item in MODEL if item["key"] == key)
        missing.append(
            {
                "key": key,
                "label_en": spec["label_en"],
                "label_ar": spec["label_ar"],
                "weight": spec["weight"],
                "reason": reason,
            }
        )

    # 1. Remediation of the highest-impact open findings.
    weighted_open = sum(SEVERITY_WEIGHT.get(item.severity, 0) for item in open_findings)
    if findings:
        closed = len(findings) - len(open_findings)
        ratio = closed / len(findings)
        factor(
            "remediation",
            ratio * 100,
            100,
            f"{closed} of {len(findings)} findings resolved; {len(open_findings)} still open "
            f"(impact weight {weighted_open}).",
            action=(
                "Remediate the open critical and high findings first."
                if open_findings
                else ""
            ),
        )
    else:
        absent("remediation", "No findings have been recorded for this project yet.")

    # 2. How much of the inventory has actually been assessed.
    if assets and (recent_scans or completed_scans):
        scanned_asset_ids = {
            target.get("asset_id")
            for scan in completed_scans
            for target in (scan.targets or [])
            if isinstance(target, dict) and target.get("asset_id")
        }
        covered = len({asset.id for asset in assets if asset.id in scanned_asset_ids})
        ratio = covered / len(assets) if assets else 0.0
        factor(
            "exposure",
            ratio * 100,
            100,
            f"{covered} of {len(assets)} assets appear in a completed assessment "
            f"({len(recent_scans)} assessments in the last {FACTOR_LIMIT} days).",
            action=(
                "Run an assessment against the assets that have never been scanned."
                if covered < len(assets)
                else ""
            ),
        )
    elif assets:
        absent("exposure", "Assets are known but no assessment has completed yet.")
    else:
        absent("exposure", "No assets are known, so assessment coverage cannot be measured.")

    # 3. Assets covered by a verified, unexpired scope entry.
    scoped = [asset for asset in assets if asset.scope_id]
    if assets:
        ratio = len(scoped) / len(assets)
        factor(
            "scope",
            ratio * 100,
            100,
            f"{len(scoped)} of {len(assets)} assets belong to a recorded scope entry.",
            action=(
                "Add scope entries for the assets that are being assessed without one."
                if len(scoped) < len(assets)
                else ""
            ),
        )
    else:
        absent("scope", "No assets are known, so scope coverage cannot be measured.")

    # 4. Whether findings actually reach a detection.
    if alerts or findings:
        alerted = len(alerts)
        ratio = min(1.0, alerted / 10) if alerted else 0.0
        factor(
            "detection",
            ratio * 100,
            100,
            f"{alerted} detections raised from {len(findings)} findings; "
            f"{len(incidents)} incidents open.",
            action=(
                "Review the detection rules: findings exist without a matching detection."
                if alerted == 0
                else ""
            ),
        )
    else:
        absent("detection", "No findings or detections exist to measure detection coverage.")

    # 5. How recently the inventory was observed.
    if assets:
        fresh = [asset for asset in assets if asset.last_seen_at and asset.last_seen_at >= now - timedelta(days=STALE_LIMIT)]
        ratio = len(fresh) / len(assets)
        factor(
            "inventory",
            ratio * 100,
            100,
            f"{len(fresh)} of {len(assets)} assets were observed in the last {STALE_LIMIT} days "
            f"({len(services)} services recorded).",
            action=(
                "Re-run discovery so the inventory reflects the current estate."
                if len(fresh) < len(assets)
                else ""
            ),
        )
    else:
        absent("inventory", "No assets are known, so inventory freshness cannot be measured.")

    # 6. Whether captured evidence carries an integrity hash.
    if evidence:
        hashed = [item for item in evidence if item.raw_sha256]
        ratio = len(hashed) / len(evidence)
        factor(
            "integrity",
            ratio * 100,
            100,
            f"{len(hashed)} of {len(evidence)} evidence records carry a SHA-256 digest.",
            action=(
                "Record a SHA-256 digest for the evidence that lacks one."
                if len(hashed) < len(evidence)
                else ""
            ),
        )
    else:
        absent("integrity", "No evidence has been captured for this project yet.")

    # 7. Are the known assets under continuous monitoring?
    if assets:
        monitored = [asset for asset in assets if asset.is_monitored]
        ratio = len(monitored) / len(assets)
        factor(
            "monitoring",
            ratio * 100,
            100,
            f"{len(monitored)} of {len(assets)} assets are marked for monitoring.",
            action=(
                "Enable monitoring for the assets that are not covered."
                if len(monitored) < len(assets)
                else ""
            ),
        )
    else:
        absent("monitoring", "No assets are known, so monitoring coverage cannot be measured.")

    # --- roll-up ------------------------------------------------------------
    measured_weight = sum(item["weight"] for item in factors)
    model_weight = sum(item["weight"] for item in MODEL)
    coverage = round((measured_weight / model_weight) * 100, 1) if model_weight else 0.0

    if measured_weight:
        raw = sum(item["earned"] / item["max"] * item["weight"] for item in factors if item["max"])
        score = round((raw / measured_weight) * 100, 1)
    else:
        score = 0.0

    if not factors:
        score = 0.0

    return {
        "project_id": project_id,
        "score": score,
        "grade": _grade(score),
        "coverage": coverage,
        "measured_weight": measured_weight,
        "model_weight": model_weight,
        "factors": factors,
        "missing_information": missing,
        "top_actions": [item for item in actions if item["action"]],
        "counts": {
            "assets": len(assets),
            "services": len(services),
            "findings": len(findings),
            "open_findings": len(open_findings),
            "critical_open": sum(1 for item in open_findings if item.severity == "critical"),
            "high_open": sum(1 for item in open_findings if item.severity == "high"),
            "scans": len(scans),
            "alerts": len(alerts),
            "incidents": len(incidents),
            "evidence": len(evidence),
        },
        "methodology": {
            "model": MODEL,
            "severity_weights": SEVERITY_WEIGHT,
            "notes": [
                "Only factors whose input data exists are scored.",
                "Weights are re-normalised over the measured factors, so an unmeasured area never inflates the score.",
                "coverage reports the share of the model that could be evaluated.",
            ],
        },
    }
