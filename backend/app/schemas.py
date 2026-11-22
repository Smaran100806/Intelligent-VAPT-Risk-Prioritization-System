"""
schemas.py — Pydantic v2 request/response schemas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Shared base config
# ---------------------------------------------------------------------------

class _Base(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------

class AssetCreate(_Base):
    name: str = Field(..., min_length=1, max_length=128)
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    asset_type: str = Field(..., description="web_application | api | host | database | network_device")
    business_unit: Optional[str] = None
    criticality: int = Field(default=3, ge=1, le=5)
    exposure: str = Field(default="internal", description="internet-facing | dmz | internal | isolated")
    owner: Optional[str] = None


class AssetResponse(AssetCreate):
    id: int
    created_at: datetime


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanCreate(_Base):
    scanner_name: str
    scan_date: datetime
    target_range: Optional[str] = None
    status: str = "completed"


class ScanResponse(ScanCreate):
    id: int
    created_at: datetime


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------

class VulnerabilityCreate(_Base):
    scan_id: Optional[int] = None          # set by upload endpoint
    asset_id: Optional[int] = None
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: str
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    vuln_type: Optional[str] = None
    exploit_available: bool = False
    in_threat_feed: bool = False
    auth_required: bool = False
    attack_vector: Optional[str] = None
    historical_recurrence: int = 0
    days_since_last_scan: int = 0


class VulnerabilityResponse(VulnerabilityCreate):
    id: int
    priority_score: Optional[float] = None
    risk_tier: Optional[str] = None
    is_remediated: bool
    discovered_at: datetime
    explainability: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Scan upload payload
# ---------------------------------------------------------------------------

class ScanUploadPayload(_Base):
    """Full scan import: metadata + list of findings."""
    scanner_name: str
    scan_date: datetime
    target_range: Optional[str] = None
    vulnerabilities: List[VulnerabilityCreate]


class ScanUploadResponse(_Base):
    scan_id: int
    total_findings: int
    scored: int
    skipped: int


# ---------------------------------------------------------------------------
# CVSS vs ML comparison
# ---------------------------------------------------------------------------

class ComparisonRow(_Base):
    vuln_id: int
    title: str
    cvss_score: float
    cvss_rank: int
    ml_score: float
    ml_rank: int
    delta: int              # ml_rank - cvss_rank  (negative = promoted by ML)
    reason: str             # human-readable explanation of delta


class ComparisonResponse(_Base):
    rows: List[ComparisonRow]
    total: int
    promoted_count: int     # ML ranked higher than CVSS
    demoted_count: int      # ML ranked lower than CVSS
    unchanged_count: int


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class DashboardStats(_Base):
    total_vulns: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    remediated_count: int
    noise_deprioritized_pct: float          # % of medium/low with priority_score < 30
    top_risks: List[VulnerabilityResponse]  # top 5 by priority_score
    severity_distribution: Dict[str, int]  # {"critical": N, "high": N, ...}
    risk_tier_distribution: Dict[str, int] # {"Critical": N, ...}
