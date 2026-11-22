"""
main.py — FastAPI application entry point.
"""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict
from unittest import result

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.auth import verify_api_key
from app.database import SessionLocal, create_tables
from app.ingest import ingest_scan
from app.ml_service import get_model_metadata
from app.models import Asset, Scan, Vulnerability, VulnerabilityHistory
from app.routers import assets, comparison, dashboard, scans, vulnerabilities

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    logger.info("Database tables verified / created.")
    yield
    logger.info("Application shutting down.")


app = FastAPI(
    title="Intelligent VAPT Risk Prioritization System",
    description="Context-Aware ML Vulnerability Triage and Risk Scoring API.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"])
app.include_router(comparison.router, prefix="/api/comparison", tags=["comparison"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["dashboard"])


@app.get("/health", tags=["meta"])
def health_check() -> Dict[str, str]:
    return {"status": "ok", "version": app.version}


@app.get("/api/model/metadata", tags=["meta"])
def model_metadata() -> Dict[str, Any]:
    return get_model_metadata()


def _load_json(filename: str) -> Any:
    path = _DATA_DIR / filename
    if not path.exists():
        raise FileNotFoundError(f"Seed file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.post("/api/seed", tags=["meta"])
def seed_database(reset: bool = False, _auth: bool = Depends(verify_api_key)) -> Dict[str, Any]:
    """
    Populate seed assets and sample scan findings.
    When reset=True, purges previous data in FK-safe order before loading.
    """
    db: Session = SessionLocal()
    try:
        if reset:
            # Delete in FK-safe order
            db.execute(delete(Vulnerability))
            db.execute(delete(VulnerabilityHistory))
            db.execute(delete(Scan))
            db.execute(delete(Asset))
            db.commit()
            logger.info("Existing database tables purged for reset.")

        # 1. Seed Assets
        assets_data = _load_json("seed_assets.json")
        assets_data = [a for a in assets_data if "_comment" not in a or len(a) > 1]

        assets_created = 0
        for a in assets_data:
            existing = db.execute(
                delete(Asset).where(Asset.ip_address == a.get("ip_address"))
            ) if reset else None

            asset_obj = Asset(
                name=a["name"],
                ip_address=a.get("ip_address"),
                hostname=a.get("hostname"),
                asset_type=a["asset_type"],
                business_unit=a.get("business_unit"),
                criticality=a.get("criticality", 3),
                exposure=a.get("exposure", "internal"),
                owner=a.get("owner"),
            )
            db.add(asset_obj)
            assets_created += 1

        db.commit()

        # 2. Seed Scan via unified ingest_scan pipeline
        scan_doc = _load_json("sample_vapt_scan.json")
        meta = scan_doc.get("scan_metadata", {})
        findings = scan_doc.get("findings", [])

        result = ingest_scan(meta, findings, db)
        scan, findings_scored = result.scan, result.scored

        return {
            "message": "Seed data loaded successfully.",
            "assets_created": assets_created,
            "findings_scored": findings_scored,
            "scan_id": scan.id,
        }

    except Exception as exc:
        db.rollback()
        logger.exception("Seed failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Seed failed: {exc}") from exc
    finally:
        db.close()
