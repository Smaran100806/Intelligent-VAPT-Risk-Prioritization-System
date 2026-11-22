"""
models.py — SQLAlchemy ORM models (SQLAlchemy 2.x style).
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean,
    DateTime, ForeignKey, Text,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------

class Asset(Base):
    __tablename__ = "assets"

    id            = Column(Integer, primary_key=True, index=True)
    name          = Column(String(128), nullable=False)
    ip_address    = Column(String(45), nullable=True, unique=True)
    hostname      = Column(String(255), nullable=True)
    asset_type    = Column(String(64), nullable=False)          # web_application | api | host | database | network_device
    business_unit = Column(String(128), nullable=True)
    criticality   = Column(Integer, default=3)                  # 1–5
    exposure      = Column(String(32), default="internal")      # internet-facing | dmz | internal | isolated
    owner         = Column(String(128), nullable=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())

    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class Scan(Base):
    __tablename__ = "scans"

    id           = Column(Integer, primary_key=True, index=True)
    scanner_name = Column(String(64), nullable=False)
    scan_date    = Column(DateTime(timezone=True), nullable=False)
    target_range = Column(String(256), nullable=True)
    status       = Column(String(32), default="completed")
    created_at   = Column(DateTime(timezone=True), server_default=func.now())

    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id                    = Column(Integer, primary_key=True, index=True)
    scan_id               = Column(Integer, ForeignKey("scans.id"), nullable=False)
    asset_id              = Column(Integer, ForeignKey("assets.id"), nullable=True)

    cve_id                = Column(String(32), nullable=True, index=True)
    title                 = Column(String(256), nullable=False)
    description           = Column(Text, nullable=True)
    severity              = Column(String(32), nullable=False)   # critical | high | medium | low | informational
    cvss_score            = Column(Float, nullable=True)
    cvss_vector           = Column(String(128), nullable=True)

    # ML feature inputs
    vuln_type             = Column(String(64), nullable=True)    # rce | sqli | xss | lfi | ssrf | other
    exploit_available     = Column(Boolean, default=False)
    in_threat_feed        = Column(Boolean, default=False)
    auth_required         = Column(Boolean, default=False)
    attack_vector         = Column(String(32), nullable=True)    # network | adjacent | local | physical
    historical_recurrence = Column(Integer, default=0)
    days_since_last_scan  = Column(Integer, default=0)

    # ML outputs
    priority_score        = Column(Float, nullable=True)
    risk_tier             = Column(String(32), nullable=True)    # Critical | High | Medium | Low
    model_used            = Column(String(32), nullable=True)    # regressor | heuristic

    is_remediated         = Column(Boolean, default=False)
    discovered_at         = Column(DateTime(timezone=True), server_default=func.now())

    scan  = relationship("Scan", back_populates="vulnerabilities")
    asset = relationship("Asset", back_populates="vulnerabilities")


# ---------------------------------------------------------------------------
# VulnerabilityHistory
# ---------------------------------------------------------------------------

class VulnerabilityHistory(Base):
    __tablename__ = "vulnerability_history"

    id               = Column(Integer, primary_key=True, index=True)
    cve_id           = Column(String(64), nullable=True, index=True)
    finding_key      = Column(String(256), nullable=True, index=True)  # cve:<id> or title:<normalized>
    asset_id         = Column(Integer, ForeignKey("assets.id"), nullable=True)
    first_seen       = Column(DateTime(timezone=True), server_default=func.now())
    last_seen        = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    recurrence_count = Column(Integer, default=1)
