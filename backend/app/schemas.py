"""
schemas.py — Pydantic v2 request/response schemas.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Literal

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
    scan_id: Optional[int] = None
    asset_id: Optional[int] = None
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: Literal["critical", "high", "medium", "low", "informational"] = "medium"
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    vuln_type: Optional[str] = None
    exploit_available: bool = False
    in_threat_feed: bool = False
    auth_required: bool = False
    attack_vector: Optional[str] = None
    historical_recurrence: int = 0
    days_since_last_scan: int = 0


class ScannerFinding(_Base):
    """Raw finding format ingested from scanner JSON or CSV."""
    plugin_id: Optional[int] = None
    cve_id: Optional[str] = None
    title: str
    severity: Literal["critical", "high", "medium", "low", "informational"] = "medium"
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    vuln_type: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    description: Optional[str] = None
    solution: Optional[str] = None
    exploit_available: bool = False
    in_threat_feed: bool = False
    auth_required: bool = False
    attack_vector: Optional[str] = None
    historical_recurrence: int = 0
    days_since_last_scan: int = 0


class VulnerabilityResponse(VulnerabilityCreate):
    id: int
    asset_name: Optional[str] = None
    asset_criticality: Optional[int] = None
    asset_exposure: Optional[str] = None
    priority_score: Optional[float] = None
    risk_tier: Optional[Literal["Critical", "High", "Medium", "Low"]] = None
    is_remediated: bool
    discovered_at: datetime
    explainability: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Scan upload payload (supports standard & raw scanner shapes)
# ---------------------------------------------------------------------------

class ScanMetadata(_Base):
    scanner: Optional[str] = "Nessus / Generic Scanner"
    scan_id: Optional[str] = None
    scan_date: Optional[datetime] = None
    policy: Optional[str] = None
    target: Optional[str] = None


class RawScanDocument(_Base):
    """Raw scanner export shape: {scan_metadata: {...}, findings: [...]}"""
    scan_metadata: Optional[ScanMetadata] = Field(default_factory=ScanMetadata)
    findings: List[ScannerFinding]


class ScanUploadPayload(_Base):
    """Legacy or custom wrapper shape."""
    scanner_name: Optional[str] = None
    scan_date: Optional[datetime] = None
    target_range: Optional[str] = None
    vulnerabilities: Optional[List[ScannerFinding]] = None
    # Support direct scanner document payload
    scan_metadata: Optional[ScanMetadata] = None
    findings: Optional[List[ScannerFinding]] = None


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
    asset_name: str
    risk_tier: str
    cvss_score: float
    cvss_rank: int
    ml_score: float
    ml_rank: int
    delta: int              # ml_rank - cvss_rank (negative = promoted)
    reason: str


class ComparisonResponse(_Base):
    rows: List[ComparisonRow]
    total: int
    promoted_count: int
    demoted_count: int
    unchanged_count: int


class FeatureImportanceItem(_Base):
    feature: str
    importance: float


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class DashboardStats(_Base):
    total_vulns: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    critical_tier_count: int
    high_tier_count: int
    medium_tier_count: int
    low_tier_count: int
    remediated_count: int
    noise_deprioritized_pct: float
    top_risks: List[VulnerabilityResponse]
    severity_distribution: Dict[str, int]
    risk_tier_distribution: Dict[str, int]
