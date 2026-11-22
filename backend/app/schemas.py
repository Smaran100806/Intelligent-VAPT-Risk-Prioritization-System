"""
schemas.py — Pydantic v2 request/response schemas.

Keeps API contracts separate from ORM models.
Full validation rules to be added in subsequent milestones.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field, ConfigDict


# ---------------------------------------------------------------------------
# Shared base config
# ---------------------------------------------------------------------------

class _Base(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# User schemas
# ---------------------------------------------------------------------------

class UserCreate(_Base):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserResponse(_Base):
    id: int
    username: str
    email: EmailStr
    is_active: bool
    is_admin: bool
    created_at: datetime


class Token(_Base):
    access_token: str
    token_type: str = "bearer"


# ---------------------------------------------------------------------------
# Asset schemas
# ---------------------------------------------------------------------------

class AssetCreate(_Base):
    name: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    asset_type: str
    business_unit: Optional[str] = None
    criticality: int = Field(default=3, ge=1, le=5)
    owner: Optional[str] = None


class AssetResponse(AssetCreate):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Vulnerability schemas
# ---------------------------------------------------------------------------

class VulnerabilityCreate(_Base):
    asset_id: int
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None


class VulnerabilityResponse(VulnerabilityCreate):
    id: int
    is_remediated: bool
    discovered_at: datetime
    remediated_at: Optional[datetime] = None
    risk_score: Optional["RiskScoreResponse"] = None


# ---------------------------------------------------------------------------
# Risk Score schemas
# ---------------------------------------------------------------------------

class RiskScoreResponse(_Base):
    id: int
    vulnerability_id: int
    composite_score: float
    exploitability_score: Optional[float] = None
    asset_criticality_weight: Optional[float] = None
    threat_intel_boost: float
    model_version: Optional[str] = None
    computed_at: datetime


# ---------------------------------------------------------------------------
# Scan import schema (for ingesting scanner JSON output)
# ---------------------------------------------------------------------------

class ScanImportPayload(_Base):
    scanner: str                           # e.g. "nessus", "openvas", "burp"
    scan_date: datetime
    target_asset_id: int
    findings: List[VulnerabilityCreate]
