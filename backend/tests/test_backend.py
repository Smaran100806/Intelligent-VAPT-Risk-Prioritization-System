"""
test_backend.py — Unit test suite for VAPT backend operations.
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import create_tables, SessionLocal
from app.main import seed_database
from app.routers.comparison import cvss_vs_ml_comparison, get_feature_importance
from app.routers.vulnerabilities import list_vulnerabilities
from app.routers.dashboard import get_dashboard
from app.ingest import ingest_scan

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    create_tables()
    seed_database(reset=True, _auth=True)


def test_seed_reset_idempotence():
    res1 = seed_database(reset=True, _auth=True)
    assert res1["assets_created"] == 12
    assert res1["findings_scored"] == 15

    res2 = seed_database(reset=True, _auth=True)
    assert res2["assets_created"] == 12
    assert res2["findings_scored"] == 15


def test_comparison_endpoint():
    db = SessionLocal()
    try:
        data = cvss_vs_ml_comparison(db)
        assert len(data.rows) == 15
        first = data.rows[0]
        assert first.asset_name != ""
        assert first.risk_tier in ("Critical", "High", "Medium", "Low")
        assert first.cvss_score > 0
        assert first.ml_score > 0
        assert first.delta is not None
    finally:
        db.close()


def test_feature_importance_endpoint():
    items = get_feature_importance()
    assert len(items) > 0
    assert items[0].feature != ""
    assert items[0].importance > 0
    vals = [i.importance for i in items]
    assert vals == sorted(vals, reverse=True)


def test_vulnerabilities_fields():
    db = SessionLocal()
    try:
        vulns = list_vulnerabilities(db=db)
        assert len(vulns) >= 15
        first = vulns[0]
        assert first.asset_name is not None
        assert first.asset_criticality is not None
        assert first.asset_exposure is not None
        assert first.priority_score is not None
        assert first.risk_tier in ("Critical", "High", "Medium", "Low")
    finally:
        db.close()


def test_raw_scanner_ingestion_and_parity():
    db = SessionLocal()
    try:
        raw_meta = {
            "scanner": "Enterprise Nessus Test",
            "target": "192.168.1.100",
        }
        findings = [
            {
                "plugin_id": 99901,
                "title": "SQL Injection in Payment Processing API (Production Gateway)",
                "severity": "high",
                "cvss_score": 8.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "vuln_type": "sqli",
                "host": "192.168.1.100",
                "exploit_available": True,
                "in_threat_feed": True,
                "auth_required": False,
                "attack_vector": "network",
                "historical_recurrence": 3,
                "days_since_last_scan": 14,
            }
        ]

        scan, scored, skipped = ingest_scan(raw_meta, findings, db)
        assert scored == 1
        assert skipped == 0

        # Retrieve and verify parity
        vulns = list_vulnerabilities(db=db)
        target_vuln = [v for v in vulns if v.scan_id == scan.id][0]
        assert target_vuln.priority_score == 100.0
        assert target_vuln.risk_tier == "Critical"
        assert target_vuln.asset_name == "prod-payment-db"
    finally:
        db.close()
