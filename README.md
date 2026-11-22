# Intelligent VAPT Risk Prioritization System

## Overview
An AI/ML-powered Vulnerability Assessment and Penetration Testing (VAPT) risk prioritization system that automatically ranks vulnerabilities by business impact, exploitability, and asset criticality — helping security teams triage faster and remediate smarter.

---

## Architecture

```
Intelligent-VAPT-Risk-Prioritization-System/
├── backend/                  # FastAPI REST API
│   ├── app/
│   │   ├── main.py           # App entry point, route registration
│   │   ├── models.py         # SQLAlchemy ORM models
│   │   ├── schemas.py        # Pydantic request/response schemas
│   │   ├── database.py       # DB session, engine setup
│   │   └── ml_service.py     # ML inference wrapper
│   └── requirements.txt      # Python dependencies
│
├── ml/                       # ML pipeline (training & evaluation)
│   ├── train_model.py        # Model training script
│   ├── generate_synthetic_data.py  # Synthetic VAPT data generator
│   ├── evaluate.py           # Model evaluation & metrics
│   └── artifacts/            # Saved models (.pkl) — git-ignored
│
├── data/                     # Seed & sample data
│   ├── sample_vapt_scan.json # Example scanner output
│   └── seed_assets.json      # Asset inventory seed data
│
├── frontend/                 # React SPA
│   ├── src/
│   │   ├── components/       # Reusable UI components
│   │   ├── pages/            # Route-level page components
│   │   └── services/
│   │       └── api.js        # Axios/fetch API client
│   └── package.json          # Node dependencies & scripts
│
├── README.md
└── .gitignore
```

---

## Tech Stack

| Layer      | Technology                              |
|------------|-----------------------------------------|
| Backend    | Python 3.11+, FastAPI, SQLAlchemy       |
| Database   | SQLite (dev) → PostgreSQL (prod)        |
| ML         | scikit-learn, XGBoost, pandas, numpy    |
| Frontend   | React 18, Axios, Recharts, Tailwind CSS |
| Auth       | JWT (python-jose)                       |
| Dev Tools  | uvicorn, pydantic v2, alembic           |

---

## Key Features (Planned)
- **Automated Risk Scoring** — CVSS + asset criticality + threat intelligence → unified risk score
- **ML Prioritization Model** — XGBoost classifier trained on historical VAPT data
- **Asset Inventory Management** — CRUD for hosts, services, and business units
- **Interactive Dashboard** — Severity heatmaps, trend charts, remediation queues
- **Scan Import** — Ingest Nessus / OpenVAS / Burp Suite JSON/XML output

---

## Getting Started

### Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### ML Pipeline
```bash
cd ml
python generate_synthetic_data.py   # create training data
python train_model.py               # train & save model artifact
python evaluate.py                  # print metrics
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

---

## Environment Variables
Copy `.env.example` to `.env` and fill in values:
```
DATABASE_URL=sqlite:///./vapt.db
SECRET_KEY=your-secret-key
ML_MODEL_PATH=ml/artifacts/risk_model.pkl
```

---

## License
MIT
