"""
ingest.py — Unified ingestion engine for VAPT scanner findings.

Used by:
  - POST /api/seed
  - POST /api/scans/upload
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, NamedTuple, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ml_service import score_vulnerability
from app.models import Asset, Scan, Vulnerability, VulnerabilityHistory
from app.schemas import ScannerFinding

logger = logging.getLogger(__name__)


def _infer_attack_vector(cvss_vector: Optional[str]) -> str:
    vec = cvss_vector or ""
    if "AV:N" in vec:
        return "network"
    if "AV:A" in vec:
        return "adjacent"
    if "AV:L" in vec:
        return "local"
    if "AV:P" in vec:
        return "physical"
    return "network"


def _infer_vuln_type(title: str) -> str:
    """Classify from the title using word boundaries so 'resource' is not treated as RCE."""
    t = (title or "").lower()
    if re.search(r"\bsqli\b|\bsql injection\b|\bsql\b", t):
        return "sqli"
    if re.search(r"cross-site|\bxss\b", t):
        return "xss"
    if re.search(r"remote code execution|\brce\b|buffer overflow", t):
        return "rce"
    if re.search(r"file read|\blfi\b|traversal", t):
        return "lfi"
    if re.search(r"\bssrf\b", t):
        return "ssrf"
    return "other"


def _finding_key(cve_id: Optional[str], title: str) -> str:
    cve = (cve_id or "").strip()
    if cve:
        return f"cve:{cve}"
    normalized = " ".join((title or "").lower().split())
    return f"title:{normalized}"


class IngestResult(NamedTuple):
    scan: Scan
    scored: int
    skipped: int
    warnings: List[str]


def ingest_scan(
    scan_meta: Dict[str, Any],
    findings: List[ScannerFinding | Dict[str, Any]],
    db: Session,
) -> IngestResult:
    """
    Unified scanner ingestion:
      - Resolves target asset by host IP
      - Preserves finding's explicit vuln_type, auth_required, days_since_last_scan, attack_vector
      - Updates VulnerabilityHistory recurrence counters
      - Evaluates ML risk scoring and stores priority_score & risk_tier
    """
    raw_date = scan_meta.get("scan_date")
    if isinstance(raw_date, str):
        try:
            scan_date = datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
        except Exception:
            scan_date = datetime.now(timezone.utc)
    elif isinstance(raw_date, datetime):
        scan_date = raw_date
    else:
        scan_date = datetime.now(timezone.utc)

    scan = Scan(
        scanner_name=scan_meta.get("scanner") or scan_meta.get("scanner_name") or "Automated Scanner",
        scan_date=scan_date,
        target_range=scan_meta.get("target") or scan_meta.get("target_range"),
        status="completed",
    )
    db.add(scan)
    db.flush()

    # First asset for an IP wins so duplicate rows cannot hide behind a later insert.
    all_assets = db.execute(select(Asset).order_by(Asset.id.asc())).scalars().all()
    ip_to_asset: Dict[str, Asset] = {}
    for asset_row in all_assets:
        if asset_row.ip_address and asset_row.ip_address not in ip_to_asset:
            ip_to_asset[asset_row.ip_address] = asset_row
    id_to_asset: Dict[int, Asset] = {a.id: a for a in all_assets}

    scored_count = 0
    skipped_count = 0
    warnings: List[str] = []

    for item in findings:
        if isinstance(item, ScannerFinding):
            f_dict = item.model_dump()
        else:
            f_dict = dict(item)

        title = f_dict.get("title")
        if not title:
            skipped_count += 1
            continue

        host_ip = f_dict.get("host")
        asset_id = f_dict.get("asset_id")

        asset: Optional[Asset] = None
        if host_ip and host_ip in ip_to_asset:
            asset = ip_to_asset[host_ip]
        elif asset_id and asset_id in id_to_asset:
            asset = id_to_asset[asset_id]

        asset_dict: Dict[str, Any] = {}
        if asset:
            asset_dict = {
                "criticality": asset.criticality,
                "exposure": asset.exposure,
            }
        else:
            asset_dict = {"criticality": 3, "exposure": "internal"}
            target = host_ip or (f"asset_id {asset_id}" if asset_id else "unspecified host")
            warnings.append(
                f"{title}: no matching asset for {target}; scored as criticality 3 and exposure internal"
            )

        # Context-aware attribute resolution with clean fallbacks
        cvss_vector = f_dict.get("cvss_vector")
        attack_vector = f_dict.get("attack_vector") or _infer_attack_vector(cvss_vector)
        vuln_type = f_dict.get("vuln_type") or _infer_vuln_type(title)
        auth_required = bool(f_dict.get("auth_required", False))
        days_since_last_scan = int(f_dict.get("days_since_last_scan") or 0)
        exploit_available = bool(f_dict.get("exploit_available", False))
        in_threat_feed = bool(f_dict.get("in_threat_feed", False))

        cve_id = f_dict.get("cve_id")
        recurrence = int(f_dict.get("historical_recurrence") or 0)
        finding_key = _finding_key(cve_id, title)

        # Track recurrence for every finding, including those without a CVE.
        asset_id_val = asset.id if asset else None
        hist_stmt = select(VulnerabilityHistory).where(
            VulnerabilityHistory.finding_key == finding_key,
            VulnerabilityHistory.asset_id == asset_id_val,
        )
        hist = db.execute(hist_stmt).scalar_one_or_none()
        if hist:
            hist.recurrence_count += 1
            hist.last_seen = datetime.now(timezone.utc)
            recurrence = hist.recurrence_count
        else:
            hist = VulnerabilityHistory(
                cve_id=(cve_id or None),
                finding_key=finding_key,
                asset_id=asset_id_val,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
                recurrence_count=max(recurrence, 1),
            )
            db.add(hist)
            recurrence = hist.recurrence_count

        vuln_features = {
            "cvss_score": f_dict.get("cvss_score"),
            "vuln_type": vuln_type,
            "exploit_available": exploit_available,
            "in_threat_feed": in_threat_feed,
            "auth_required": auth_required,
            "attack_vector": attack_vector,
            "historical_recurrence": recurrence,
            "days_since_last_scan": days_since_last_scan,
        }

        ml_eval = score_vulnerability(vuln_features, asset_dict)
        for warning in ml_eval.get("warnings") or []:
            warnings.append(f"{title}: {warning}")

        vuln = Vulnerability(
            scan_id=scan.id,
            asset_id=asset.id if asset else None,
            cve_id=cve_id,
            title=title,
            description=f_dict.get("description"),
            severity=f_dict.get("severity", "medium"),
            cvss_score=f_dict.get("cvss_score"),
            cvss_vector=cvss_vector,
            vuln_type=vuln_type,
            exploit_available=exploit_available,
            in_threat_feed=in_threat_feed,
            auth_required=auth_required,
            attack_vector=attack_vector,
            historical_recurrence=recurrence,
            days_since_last_scan=days_since_last_scan,
            priority_score=ml_eval["priority_score"],
            risk_tier=ml_eval["risk_tier"],
            model_used=ml_eval.get("model_used"),
            is_remediated=False,
        )
        db.add(vuln)
        scored_count += 1

    db.commit()
    return IngestResult(scan, scored_count, skipped_count, warnings)
