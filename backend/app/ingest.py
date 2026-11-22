"""
ingest.py — Unified ingestion engine for VAPT scanner findings.

Used by:
  - POST /api/seed
  - POST /api/scans/upload
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

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
    t = (title or "").lower()
    if "sql" in t:
        return "sqli"
    if "cross-site" in t or "xss" in t:
        return "xss"
    if "remote code execution" in t or "rce" in t or "buffer overflow" in t:
        return "rce"
    if "file read" in t or "lfi" in t or "traversal" in t:
        return "lfi"
    if "ssrf" in t:
        return "ssrf"
    return "other"


def ingest_scan(
    scan_meta: Dict[str, Any],
    findings: List[ScannerFinding | Dict[str, Any]],
    db: Session,
) -> Tuple[Scan, int, int]:
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

    # Pre-index all assets by IP and by ID
    all_assets = db.execute(select(Asset)).scalars().all()
    ip_to_asset: Dict[str, Asset] = {a.ip_address: a for a in all_assets if a.ip_address}
    id_to_asset: Dict[int, Asset] = {a.id: a for a in all_assets}

    scored_count = 0
    skipped_count = 0

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

        # Track recurrence across scans
        if cve_id:
            asset_id_val = asset.id if asset else None
            hist_stmt = select(VulnerabilityHistory).where(
                VulnerabilityHistory.cve_id == cve_id,
                VulnerabilityHistory.asset_id == asset_id_val,
            )
            hist = db.execute(hist_stmt).scalar_one_or_none()
            if hist:
                hist.recurrence_count += 1
                hist.last_seen = datetime.now(timezone.utc)
                recurrence = hist.recurrence_count
            else:
                hist = VulnerabilityHistory(
                    cve_id=cve_id,
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
            is_remediated=False,
        )
        db.add(vuln)
        scored_count += 1

    db.commit()
    return scan, scored_count, skipped_count
