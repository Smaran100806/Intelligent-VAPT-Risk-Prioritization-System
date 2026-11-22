"""
main.py — FastAPI application entry point.

Registers all routers, CORS middleware, DB initialisation on startup,
and a /api/seed endpoint that loads seed data from the data/ directory.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.database import SessionLocal, create_tables
from app.ml_service import score_vulnerability
from app.models import Asset, Scan, Vulnerability, VulnerabilityHistory

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data directory (project root / data)
# ---------------------------------------------------------------------------

_DATA_DIR = Path(__file__).parent.parent.parent / "data"


# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create DB tables on startup."""
    create_tables()
    logger.info("Database tables verified / created.")
    yield
    logger.info("Application shutting down.")


# ---------------------------------------------------------------------------
# App instance
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Intelligent VAPT Risk Prioritization System",
    description=(
        "AI-powered vulnerability triage and risk scoring API. "
        "Combines ML models with contextual asset data to rank findings."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS — allow frontend dev servers
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

from app.routers import assets, scans, vulnerabilities, comparison, dashboard  # noqa: E402

app.include_router(assets.router,          prefix="/api/assets",          tags=["assets"])
app.include_router(scans.router,           prefix="/api/scans",           tags=["scans"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"])
app.include_router(comparison.router,      prefix="/api/comparison",      tags=["comparison"])
app.include_router(dashboard.router,       prefix="/api/dashboard",       tags=["dashboard"])


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
async def health_check() -> dict:
    return {"status": "ok", "version": app.version}


@app.get("/", tags=["meta"])
async def root() -> dict:
    return {"message": "VAPT Risk Prioritization API — see /docs for Swagger UI"}


# ---------------------------------------------------------------------------
# Seed endpoint
# ---------------------------------------------------------------------------

def _load_json(filename: str) -> Any:
    path = _DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Seed file not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _resolve_exposure(asset_type: str, ip: str | None) -> str:
    """Guess exposure from asset type / IP for seed data that lacks the field."""
    if ip and ip.startswith("10.0."):
        return "dmz"
    if asset_type in ("web_application", "api"):
        return "internet-facing"
    return "internal"


@app.post("/api/seed", tags=["meta"])
def seed_database() -> Dict[str, Any]:
    """
    Load seed data from data/seed_assets.json and data/sample_vapt_scan.json,
    persist them to the database, run ML scoring on each finding.

    Idempotent: existing records are skipped (not duplicated).
    """
    db: Session = SessionLocal()
    try:
        # ----------------------------------------------------------------
        # 1. Load assets
        # ----------------------------------------------------------------
        assets_data = _load_json("seed_assets.json")
        # Filter out comment entries
        assets_data = [a for a in assets_data if "_comment" not in a or len(a) > 1]

        created_assets: Dict[str, int] = {}  # ip_address -> asset.id
        for a in assets_data:
            if "_comment" in a and len(a) == 1:
                continue
            # Skip if ip already seeded
            from sqlalchemy import select as sa_select
            existing = db.execute(
                sa_select(Asset).where(Asset.ip_address == a.get("ip_address"))
            ).scalar_one_or_none()

            if existing:
                created_assets[a.get("ip_address", "")] = existing.id
                continue

            exposure = a.get("exposure") or _resolve_exposure(
                a.get("asset_type", "host"), a.get("ip_address")
            )

            asset = Asset(
                name=a["name"],
                ip_address=a.get("ip_address"),
                hostname=a.get("hostname"),
                asset_type=a.get("asset_type", "host"),
                business_unit=a.get("business_unit"),
                criticality=a.get("criticality", 3),
                exposure=exposure,
                owner=a.get("owner"),
            )
            db.add(asset)
            db.flush()
            created_assets[a.get("ip_address", "")] = asset.id

        db.flush()

        # ----------------------------------------------------------------
        # 2. Load scan + findings
        # ----------------------------------------------------------------
        scan_data = _load_json("sample_vapt_scan.json")
        meta = scan_data.get("scan_metadata", {})
        findings = scan_data.get("findings", [])

        from sqlalchemy import select as sa_select

        # Check if this scan already exists (by scanner + date)
        scan_date_str = meta.get("scan_date", datetime.now(timezone.utc).isoformat())
        try:
            scan_date = datetime.fromisoformat(scan_date_str.replace("Z", "+00:00"))
        except ValueError:
            scan_date = datetime.now(timezone.utc)

        existing_scan = db.execute(
            sa_select(Scan).where(
                Scan.scanner_name == meta.get("scanner", "nessus"),
                Scan.scan_date == scan_date,
            )
        ).scalar_one_or_none()

        if existing_scan:
            db.rollback()
            return {
                "message": "Seed data already loaded.",
                "assets_total": len(assets_data),
                "findings_total": len(findings),
            }

        scan = Scan(
            scanner_name=meta.get("scanner", "nessus"),
            scan_date=scan_date,
            target_range=meta.get("target"),
            status="completed",
        )
        db.add(scan)
        db.flush()

        # Reload assets from DB for complete data
        all_assets = db.execute(sa_select(Asset)).scalars().all()
        ip_to_asset: Dict[str, Asset] = {a.ip_address: a for a in all_assets if a.ip_address}

        for finding in findings:
            host_ip = finding.get("host")
            asset = ip_to_asset.get(host_ip)

            asset_dict: Dict[str, Any] = {}
            if asset:
                asset_dict = {"criticality": asset.criticality, "exposure": asset.exposure}

            # Infer attack_vector from CVSS vector string
            cvss_vector = finding.get("cvss_vector", "")
            if "AV:N" in cvss_vector:
                attack_vector = "network"
            elif "AV:A" in cvss_vector:
                attack_vector = "adjacent"
            elif "AV:L" in cvss_vector:
                attack_vector = "local"
            elif "AV:P" in cvss_vector:
                attack_vector = "physical"
            else:
                attack_vector = "network"

            # Infer vuln_type from title keywords
            title_lower = finding.get("title", "").lower()
            if "remote code execution" in title_lower or "rce" in title_lower:
                vuln_type = "rce"
            elif "sql" in title_lower:
                vuln_type = "sqli"
            elif "xss" in title_lower or "cross-site" in title_lower:
                vuln_type = "xss"
            elif "file read" in title_lower or "lfi" in title_lower:
                vuln_type = "lfi"
            elif "ssrf" in title_lower:
                vuln_type = "ssrf"
            else:
                vuln_type = "other"

            cve_id = finding.get("cve_id")

            # Track recurrence
            recurrence = 0
            if cve_id:
                asset_id_val = asset.id if asset else None
                hist = db.execute(
                    sa_select(VulnerabilityHistory).where(
                        VulnerabilityHistory.cve_id == cve_id,
                        VulnerabilityHistory.asset_id == asset_id_val,
                    )
                ).scalar_one_or_none()
                if hist:
                    hist.recurrence_count += 1
                    recurrence = hist.recurrence_count
                else:
                    hist = VulnerabilityHistory(
                        cve_id=cve_id,
                        asset_id=asset_id_val,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        recurrence_count=1,
                    )
                    db.add(hist)

            vuln_dict: Dict[str, Any] = {
                "cvss_score": finding.get("cvss_score"),
                "vuln_type": vuln_type,
                "exploit_available": finding.get("exploit_available", False),
                "in_threat_feed": finding.get("in_threat_feed", False),
                "auth_required": False,
                "attack_vector": attack_vector,
                "historical_recurrence": recurrence,
                "days_since_last_scan": 0,
            }

            ml_result = score_vulnerability(vuln_dict, asset_dict)

            vuln = Vulnerability(
                scan_id=scan.id,
                asset_id=asset.id if asset else None,
                cve_id=cve_id,
                title=finding.get("title", "Unknown"),
                description=finding.get("description"),
                severity=finding.get("severity", "medium"),
                cvss_score=finding.get("cvss_score"),
                cvss_vector=finding.get("cvss_vector"),
                vuln_type=vuln_type,
                exploit_available=finding.get("exploit_available", False),
                in_threat_feed=finding.get("in_threat_feed", False),
                auth_required=False,
                attack_vector=attack_vector,
                historical_recurrence=recurrence,
                days_since_last_scan=0,
                priority_score=ml_result["priority_score"],
                risk_tier=ml_result["risk_tier"],
                is_remediated=False,
            )
            db.add(vuln)

        db.commit()
        return {
            "message": "Seed data loaded successfully.",
            "scan_id": scan.id,
            "assets_created": len(created_assets),
            "findings_scored": len(findings),
        }

    except Exception as exc:
        db.rollback()
        logger.exception("Seed failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Seed failed: {exc}") from exc
    finally:
        db.close()
