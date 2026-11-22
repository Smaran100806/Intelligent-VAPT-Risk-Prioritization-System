# Intelligent VAPT Risk Prioritization System

## Overview
An AI/ML-driven Vulnerability Assessment and Penetration Testing (VAPT) risk prioritization system that combines standard CVSS scores with asset criticality, network exposure, active threat intelligence, and historical recurrence to compute a context-aware priority score (0–100) and actionable risk tier (`Critical`, `High`, `Medium`, `Low`).

---

## Architecture

```
Intelligent-VAPT-Risk-Prioritization-System/
├── backend/                       # FastAPI REST API (SQLAlchemy + SQLite/Postgres)
│   ├── app/
│   │   ├── main.py                # FastAPI lifecycle, routes, /api/seed
│   │   ├── models.py              # Asset, Scan, Vulnerability, VulnerabilityHistory
│   │   ├── schemas.py             # Pydantic v2 schemas + scanner findings contract
│   │   ├── database.py            # SessionLocal, Base, engine
│   │   ├── ingest.py              # Unified ingestion pipeline for seed & scan uploads
│   │   ├── ml_service.py          # ML inference service + feature builder
│   │   ├── scoring_weights.py     # Single source of truth for weights and encodings
│   │   ├── auth.py                # Header-based X-API-Key security
│   │   └── routers/
│   │       ├── assets.py          # Asset inventory CRUD
│   │       ├── comparison.py      # CVSS vs ML ranking + feature importance
│   │       ├── dashboard.py       # Executive KPIs + severity distribution
│   │       ├── scans.py           # Raw & wrapped scan report upload
│   │       ├── vulnerabilities.py # Filterable prioritization queue + remediation
│   │       └── helpers.py         # Unified response serializer
│   └── requirements.txt           # Pinned backend dependencies
│
├── ml/                            # Machine Learning Pipeline
│   ├── scoring_weights.py         # Shared scoring constants & maps
│   ├── generate_synthetic_data.py # 2,500+ realistic VAPT synthetic training dataset
│   ├── train_model.py             # Gradient Boosting regressor pipeline (StandardScaler + GBR)
│   ├── evaluate.py                # Rigorous test-split evaluation (RMSE, MAE, R², Accuracy)
│   └── artifacts/
│       ├── risk_regressor.pkl     # Serialized Gradient Boosting Regressor
│       ├── feature_names.json     # Feature column names
│       ├── model_metadata.json    # Version, test metrics, feature importances
│       └── evaluation_report.json # Test metrics verification report
│
├── data/
│   ├── seed_assets.json           # 12 diverse enterprise assets (Payment DB to Isolated Sandbox)
│   ├── sample_vapt_scan.json      # 15 realistic findings with verified CVSS v3.1 vectors
│   └── synthetic_vapt_training.csv# Generated 2,500 sample training dataset
│
├── frontend/                      # React 18 SPA (Vite + Tailwind CSS + Recharts)
│   ├── src/
│   │   ├── components/            # VulnTable, ComparisonTable, FeatureImportanceChart...
│   │   ├── pages/                 # DashboardPage, VulnerabilitiesPage, ComparisonPage...
│   │   └── services/api.js        # Axios client with automated X-API-Key injection
│   └── package.json
│
├── README.md
└── .gitignore
```

---

## Machine Learning & Context-Aware Prioritization

### Scoring Formula & Weighting
The system bridges technical severity and operational business impact via a unified weighting structure:
- **CVSS Score (3.8) & Impact (2.2)**: Core vulnerability metrics.
- **Asset Criticality (4.5)**: System tier (1 = dev sandbox, 5 = core transaction database).
- **Network Exposure (5.2)**: Reachability (isolated = 0, internal = 1, dmz = 2, internet-facing = 3).
- **Exploit Availability (10.0)**: Public exploit code available.
- **Active Threat Feed (8.5)**: Actively leveraged in current campaigns.
- **Attack Vector (2.5)**: Network vs adjacent vs local.
- **Historical Recurrence (1.8)**: Recurring flaws across scan cycles.
- **Auth Required (-4.0)**: Penalty when high-privilege access is required.

### Classifier vs Regressor Decision
Risk prioritization is inherently an ordering problem rather than an arbitrary categorical bucket. We use a **Gradient Boosting Regressor** (`StandardScaler` + `GradientBoostingRegressor`) to compute a continuous `priority_score` (0–100). The discrete `risk_tier` (`Critical`, `High`, `Medium`, `Low`) is derived from calibrated score thresholds ($75 \to \text{Critical}$, $50 \to \text{High}$, $25 \to \text{Medium}$). This ensures consistent rank ordering without classifier edge-jitter.

---

## Seed Data & Demo Expectations

| Finding Title | Asset | Exposure | CVSS 3.1 | ML Score | Risk Tier | Note |
|---|---|---|---|---|---|---|
| **SQL Injection (Payment Processing API)** | prod-payment-db | Internet-facing | 8.8 | **100.0** | **Critical** | Critical asset + active exploit |
| **Apache Log4j2 JNDI RCE** | auth-api-gateway | DMZ | 10.0 | **99.5** | **Critical** | Pre-auth RCE in DMZ gateway |
| **Fortinet FortiOS SSL-VPN RCE** | core-firewall-edge | Internet-facing | 9.8 | **99.2** | **Critical** | Perimeter gateway RCE |
| **Citrix ShareFile Arbitrary Upload** | customer-portal-web | Internet-facing | 8.8 | **91.8** | **Critical** | Public exploit in the wild |
| **SQL Injection (Mock Database)** | sandbox-dev-01 | Isolated | 6.7 | **50.7** | **High/Medium** | De-escalated: isolated dummy server |
| **Deprecated TLS 1.0/1.1** | legacy-archive-nas | Isolated | 2.9 | **31.2** | **Low** | De-escalated background noise |

---

## Getting Started

### 1. Backend Setup & Run
```powershell
cd backend
python -m uvicorn app.main:app --reload --port 8000
```
- API Docs: `http://localhost:8000/docs`
- Health Probe: `http://localhost:8000/health`
- Auth Header: `X-API-Key: vapt-secure-api-key-2026` (configurable via `API_KEY` env)

### 2. Frontend Dashboard Setup & Run
```powershell
cd frontend
npm install
npm run dev
```
- Web Application: `http://localhost:3000` (or `http://localhost:5173`)
- Click **"⚡ Reset & Load Seed Demo Data"** on the dashboard to populate findings.

---

## Limitations
- **Synthetic Training Ground-Truth**: Model training labels are generated via a structured domain formula with realistic noise rather than retrospective enterprise breach data. Model-vs-CVSS comparisons validate that the machine learning pipeline accurately learns and generalises the multi-factor context weighting, rather than measuring real-world empirical breach probabilities.
- **Scanner Formats**: The ingestion engine accepts structured JSON documents (e.g. Nessus / ZAP JSON exports or generic JSON format). XML scanner reports must be converted to JSON before ingestion.
