"""
models.py — SQLAlchemy ORM models.

Tables:
  - Asset          : hosts, services, or business applications
  - Vulnerability  : findings from scanner output
  - RiskScore      : ML-computed risk score per vulnerability
  - User           : system users (analysts, admins)

All model logic and relationships to be implemented in subsequent milestones.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    Enum,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum

from app.database import Base


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "informational"


class AssetType(str, enum.Enum):
    HOST        = "host"
    WEB_APP     = "web_application"
    API         = "api"
    DATABASE    = "database"
    NETWORK     = "network_device"


# ---------------------------------------------------------------------------
# ORM Models (columns are stubs — constraints & indexes to be added)
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String(64), unique=True, nullable=False, index=True)
    email         = Column(String(128), unique=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    is_active     = Column(Boolean, default=True)
    is_admin      = Column(Boolean, default=False)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())


class Asset(Base):
    __tablename__ = "assets"

    id              = Column(Integer, primary_key=True, index=True)
    name            = Column(String(128), nullable=False)
    ip_address      = Column(String(45))          # supports IPv6
    hostname        = Column(String(255))
    asset_type      = Column(Enum(AssetType), nullable=False)
    business_unit   = Column(String(128))
    criticality     = Column(Integer, default=3)  # 1 (low) – 5 (critical)
    owner           = Column(String(128))
    created_at      = Column(DateTime(timezone=True), server_default=func.now())
    updated_at      = Column(DateTime(timezone=True), onupdate=func.now())

    vulnerabilities = relationship("Vulnerability", back_populates="asset")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id              = Column(Integer, primary_key=True, index=True)
    asset_id        = Column(Integer, ForeignKey("assets.id"), nullable=False)
    cve_id          = Column(String(32), index=True)
    title           = Column(String(256), nullable=False)
    description     = Column(Text)
    severity        = Column(Enum(SeverityLevel), nullable=False)
    cvss_score      = Column(Float)
    cvss_vector     = Column(String(128))
    is_remediated   = Column(Boolean, default=False)
    discovered_at   = Column(DateTime(timezone=True), server_default=func.now())
    remediated_at   = Column(DateTime(timezone=True), nullable=True)

    asset           = relationship("Asset", back_populates="vulnerabilities")
    risk_score      = relationship("RiskScore", back_populates="vulnerability", uselist=False)


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id                  = Column(Integer, primary_key=True, index=True)
    vulnerability_id    = Column(Integer, ForeignKey("vulnerabilities.id"), unique=True)
    composite_score     = Column(Float, nullable=False)   # 0.0 – 100.0
    exploitability_score = Column(Float)
    asset_criticality_weight = Column(Float)
    threat_intel_boost  = Column(Float, default=0.0)
    model_version       = Column(String(32))
    computed_at         = Column(DateTime(timezone=True), server_default=func.now())

    vulnerability       = relationship("Vulnerability", back_populates="risk_score")
