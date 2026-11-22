# Intelligent VAPT Risk Prioritization System

A context-aware vulnerability triage tool. It takes scanner findings, combines the CVSS score with what the affected asset is and how exposed it is, and produces a priority score (0 to 100) and a risk tier (Critical, High, Medium, Low). It also shows, for each finding, why it was ranked where it was.

---

## Table of Contents

1. [The Problem](#the-problem)
2. [What the System Does](#what-the-system-does)
3. [Novelty](#novelty)
4. [Project Structure](#project-structure)
5. [Setup and Running](#setup-and-running)
6. [Using the Dashboard](#using-the-dashboard)
7. [Scoring Method](#scoring-method)
8. [Uploading Scan Data](#uploading-scan-data)
9. [API Reference](#api-reference)
10. [Machine Learning Model](#machine-learning-model)
11. [Testing](#testing)
12. [Troubleshooting](#troubleshooting)
13. [Limitations](#limitations)

---

## The Problem

Vulnerability scanners rank findings mainly by CVSS, a score for how severe a flaw is in general. CVSS does not know where the flaw sits. The same SQL injection is an emergency on an internet-facing payment database and a low-priority item on an isolated developer sandbox. Security teams that sort by CVSS alone spend time on the wrong findings and miss the ones that matter.

## What the System Does

For every finding, the system combines:

| Input | Source | Why it matters |
|---|---|---|
| CVSS base score | Scanner | General severity |
| CVSS vector (attack vector) | Scanner | How the flaw is reached (network, adjacent, local) |
| Asset criticality (1 to 5) | Asset inventory | Business importance of the host |
| Network exposure | Asset inventory | Isolated, internal, DMZ, or internet-facing |
| Public exploit available | Scanner | Lowers the effort needed to attack |
| In active threat feed | Scanner | Being used in real campaigns |
| Authentication required | Scanner | Raises the effort needed, so the score is lowered |
| Historical recurrence | Ingest history | Repeated findings across scans |

These are turned into a priority score by a Gradient Boosting regression model. The score is then mapped to a risk tier:

| Tier | Score |
|---|---|
| Critical | 75 and above |
| High | 50 to 74.9 |
| Medium | 25 to 49.9 |
| Low | Below 25 |

The backend stores each finding with its score, tier, and the model that produced it. The React dashboard shows the results, and a comparison page shows where context changed the ranking compared with CVSS.

---

## Novelty

Honest framing matters here, so this section separates what is new from what is standard.

**What is standard:** Gradient Boosting regression, CVSS, and the general idea of risk-based prioritization. These are established tools and we do not claim to have invented them.

**What this project contributes:**

1. **A single, explicit context-aware score.** Most tools show CVSS and asset data in separate places. This project merges them into one 0 to 100 score per finding, so the analyst sees one ranking that already accounts for where the asset sits.

2. **Side-by-side evidence against CVSS.** The Comparison page shows each finding's CVSS rank next to its ML rank, with the difference highlighted. This makes the effect of context visible instead of asserting it. The reason text for each row names the context that moved it.

3. **Explanations on every score.** The "Why?" panel breaks a score into per-factor contributions, colour-coded as raising or lowering the score. Analysts can check or challenge the ranking instead of trusting a black box.

4. **Honest reporting of its own limits.** The model's agreement figure is labelled as agreement with synthetic labels, and the explanation is labelled as a formula breakdown, not model internals. The system is built to say what it does not prove.

5. **A working end-to-end pipeline.** Ingestion, asset matching, scoring, recurrence tracking, storage, API, and dashboard are connected, with a graceful heuristic fallback if the model file is missing.

**What this project does not claim:** It is not validated against real breach outcomes. The training data is synthetic and generated from a documented formula with noise. The contribution is the integrated, transparent triage workflow and its evaluation framing, not a proven predictive advantage over CVSS in the field.

---

## Project Structure

```
Intelligent-VAPT-Risk-Prioritization-System/
├── .env                          # API_KEY (create this, see Setup)
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI app, routers, /api/seed
│   │   ├── models.py             # Asset, Scan, Vulnerability, VulnerabilityHistory
│   │   ├── schemas.py            # Pydantic request and response models
│   │   ├── database.py           # SQLAlchemy engine and session (SQLite by default)
│   │   ├── ingest.py             # Shared ingestion pipeline (seed and uploads)
│   │   ├── ml_service.py         # Model loading, feature building, scoring, fallback
│   │   ├── scoring_weights.py    # Single source of truth for weights and encodings
│   │   ├── auth.py               # X-API-Key checks
│   │   ├── env.py                # Loads the root .env file
│   │   ├── body_limit.py         # Rejects uploads over 5 MB
│   │   └── routers/              # assets, scans, vulnerabilities, comparison, dashboard, helpers
│   ├── tests/test_backend.py
│   └── requirements.txt
├── ml/
│   ├── generate_synthetic_data.py  # Builds the training dataset from the scoring formula
│   ├── train_model.py              # Trains and saves the regressor and metadata
│   ├── evaluate.py                 # Evaluates on the held-out split
│   └── artifacts/                  # risk_regressor.pkl, feature_names.json, model_metadata.json
├── data/
│   ├── seed_assets.json            # 12 demo assets
│   ├── sample_vapt_scan.json       # 15 demo findings
│   └── synthetic_vapt_training.csv # 2,500 training rows
└── frontend/
    ├── src/
    │   ├── pages/                  # Dashboard, Vulnerabilities, Comparison, Assets
    │   ├── components/             # Tables, charts, badges, upload modal
    │   └── services/api.js         # Axios client with the API key header
    └── package.json
```

---

## Setup and Running

### Requirements

- Python 3.11 or newer (tested on 3.13)
- Node.js 18 or newer

### 1. Create the environment file

Create a file named `.env` in the **repository root** (the folder containing `backend/` and `frontend/`):

```
API_KEY=vapt-secure-api-key-2026
```

Without this file the backend returns `503 Service Unavailable` for seed, upload, and remediate. The file must be named exactly `.env`, not `.env.txt`.

### 2. Install backend dependencies

```powershell
cd backend
pip install -r requirements.txt
```

### 3. Start the backend (terminal 1)

```powershell
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

Check it is running at `http://localhost:8000/health`. The interactive API docs are at `http://localhost:8000/docs`.

### 4. Start the frontend (terminal 2)

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000` (or `http://localhost:5173` if that port is used).

### 5. Load demo data

On the Dashboard, click **⚡ Reset & Load Seed Demo Data**. The message should read "Loaded: 12 assets, 15 findings scored."

Reset clears all existing data, including any uploaded scans.

### Database note

The database is a local SQLite file, `backend/vapt.db`. If the schema changes, the old file can cause `NOT NULL constraint failed` errors. Stop the server, delete the file, and restart:

```powershell
cd backend
Remove-Item vapt.db -ErrorAction SilentlyContinue
```

To use PostgreSQL instead, set `DATABASE_URL` in `.env`.

---

## Using the Dashboard

The dashboard is the summary view. Each element is explained below.

### Top banner
The **Reset & Load Seed Demo Data** button replaces all data with the demo set. Use it before a demo to start from a known state.

### KPI cards

- **Total Findings Tracked:** every finding in the database, including remediated ones.
- **Critical ML Priorities:** findings whose **ML risk tier** is Critical. Counted by the model's tier, not the scanner's severity label.
- **High Risk Findings:** findings whose ML risk tier is High.
- **Noise Deprioritized:** of the findings the scanner labelled Medium, Low, or Informational, the percentage the model scored below 30. These are alerts that look serious to a scanner but are safe to deprioritize in this environment.

### Severity & Tier Breakdown

A donut chart of findings by the scanner's **original severity** (Critical, High, Medium, Low, where Low includes Informational). It shows what the scanner reported, which can be compared with the ML tiers elsewhere on the dashboard.

### Why Context Matters

Three fixed example cards that illustrate the idea:

1. An SQL injection on an internet-facing payment database is escalated to Critical.
2. The same vulnerability type on an isolated sandbox is deprioritized.
3. A file-upload flaw being exploited in the wild is prioritized because of threat intelligence.

These are static text, not live data. They explain the concept, while the tables and charts below show the live results.

**Footer:**
- **Model Version:** the trained model version and algorithm.
- **Tier Agreement:** the percentage of held-out test rows where the model predicted the same tier as the labelled data. Shows N/A if the model file is missing. This measures agreement with synthetic labels, not accuracy against real breaches.

### Top-10 Actionable Remediation Queue

The ten highest-scoring open findings, sorted by ML score. Columns:

- **#:** position in the queue.
- **Title:** the finding name. A **Why?** button appears here.
- **Asset:** the affected host.
- **CVSS:** the original score, coloured by severity band (red 9+, orange 7+, yellow 4+, green below 4).
- **ML Score:** the priority score in blue.
- **Risk Tier:** Critical, High, Medium, or Low.
- **Exploit:** a skull icon if a public exploit exists.
- **Actions:**
  - **Details** expands the row to show the full description, target exposure and criticality, the score breakdown, the CVE link, and the recommended fix.
  - **Fix** marks the finding as remediated (requires the API key).

### Vulnerabilities page

The full registry of findings.

- **Filters:** risk tier, target asset, and "Show Remediated Only."
- **Upload & Simulate Scan:** opens a window to paste or drop a JSON scan (see [Uploading Scan Data](#uploading-scan-data)).
- **Table:** click any column header to sort. Remediated rows are faded.
- **Why? chips:** each chip is one factor's contribution to the score. **Red (+)** raises the score, **green (−)** lowers it. Examples include exploit availability, exposure, threat feed, criticality, and the authentication penalty.

The breakdown is computed from the scoring formula. It describes how the score is built and is not the model's internal attribution. The interface states this.

### Comparison page

This page shows how context changes the ranking.

- **Largest ML Escalation:** the finding that moved up most compared with its CVSS rank.
- **Largest Noise Deprioritization:** the finding that moved down most.
- **Global Feature Importance:** the top factors the trained model relies on. CVSS score is the largest, followed by asset criticality, exploit availability, and exposure.
- **Live Findings Re-Ordering table:**
  - **CVSS Rank:** position if sorted by CVSS alone.
  - **ML Rank:** position after context is applied.
  - **Δ:** the change. ↑ means the model ranked it higher, ↓ means lower.
  - Rows that moved by 2 or more places are highlighted yellow.
  - **Reason:** the context behind the ranking, such as "Internet-facing perimeter" or "Isolated sandbox."

### Assets page

The asset inventory, with exposure badges (red for internet-facing, amber for DMZ, blue for internal, green for isolated). Clicking a row opens an impact profile showing criticality, the risk multiplier used in scoring (criticality × 4.5), the owner, and exposure.

---

## Scoring Method

The heuristic score that the model learns to approximate is:

```
raw = 3.8 × CVSS
    + 2.2 × CVSS impact          (CVSS × 0.55, clamped to 1.0 to 6.0)
    + 4.5 × asset criticality
    + 5.2 × exposure            (isolated 0, internal 1, DMZ 2, internet-facing 3)
    + 10.0 × exploit available  (0 or 1)
    + 8.5 × in threat feed      (0 or 1)
    + 2.5 × attack vector       (physical 0, local 1, adjacent 2, network 3)
    + 1.8 × historical recurrence
    − 4.0 × auth required       (0 or 1)

score = clamp(raw × 0.95, 5, 100)
```

All weights and mappings live in `backend/app/scoring_weights.py`. The training data generator in `ml/` uses the same file, so the training labels and the live fallback always agree.

---

## Uploading Scan Data

The upload endpoint accepts JSON in one of two shapes.

**Scanner document (preferred):**

```json
{
  "scan_metadata": { "scanner": "My Scanner", "scan_date": "2026-11-22T09:00:00Z", "target": "10.0.0.0/24" },
  "findings": [
    {
      "title": "Example finding",
      "severity": "high",
      "cvss_score": 7.5,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "host": "192.168.1.100",
      "exploit_available": true,
      "in_threat_feed": false,
      "auth_required": false,
      "historical_recurrence": 0,
      "days_since_last_scan": 5
    }
  ]
}
```

**Wrapped payload:** the same findings under `vulnerabilities`, with `scanner_name` at the top level.

Rules that matter during a demo:

- Each finding's `host` is matched to an asset's `ip_address`. Unmatched hosts are scored as criticality 3, exposure internal, and the response lists a warning.
- `attack_vector` is taken from the finding if given, otherwise inferred from the CVSS vector.
- Uploads are limited to 5 MB.
- Every upload is stored as a new scan, and recurrence increases when the same finding (same CVE, or same title for findings without one) appears again on the same asset.

Use `data/sample_vapt_scan.json` as a template.

---

## API Reference

Base URL: `http://localhost:8000`. Write endpoints require the `X-API-Key` header.

| Method | Endpoint | Purpose | Auth |
|---|---|---|---|
| GET | `/health` | Liveness check | No |
| GET | `/api/dashboard` | KPIs, distributions, top risks | No |
| GET | `/api/vulnerabilities` | List, filter by `risk_tier`, `asset_id`, `remediated`, `limit` | No |
| GET | `/api/vulnerabilities/{id}` | Single finding with full score breakdown | No |
| PATCH | `/api/vulnerabilities/{id}/remediate` | Mark as remediated | Yes |
| POST | `/api/scans/upload` | Ingest and score a scan | Yes |
| GET | `/api/scans` | List scans | No |
| GET | `/api/assets` | List assets, filter by `exposure`, `asset_type` | No |
| POST | `/api/assets` | Add an asset | Yes |
| GET | `/api/comparison/cvss-vs-ml` | CVSS rank vs ML rank for the latest scan | No |
| GET | `/api/comparison/feature-importance` | Model feature importances | No |
| GET | `/api/model/metadata` | Model status, version, and metrics | No |
| POST | `/api/seed` | Reset and load demo data | Yes |

The frontend sends the key from `.env` automatically through `frontend/src/services/api.js`.

---

## Machine Learning Model

- **Algorithm:** `StandardScaler` followed by `GradientBoostingRegressor` (120 trees, depth 4, learning rate 0.08).
- **Target:** the continuous priority score (0 to 100). The tier is derived from the score, so tiers stay consistent with the ordering.
- **Training data:** 2,500 synthetic findings generated from the scoring formula, with Gaussian noise (standard deviation 1.8). See `ml/generate_synthetic_data.py`.
- **Split:** 80 percent training, 20 percent held out, with a fixed random seed.
- **Reported results** (from `ml/artifacts/model_metadata.json`): RMSE 2.207, R² 0.978, tier agreement 94.2 percent.

Retrain with:

```powershell
cd ml
python train_model.py
```

**If `risk_regressor.pkl` is missing,** the backend logs a warning and scores every finding with the heuristic formula. The dashboard footer then shows the fallback status, and the tier agreement reads N/A. The system keeps working.

---

## Testing

From the `backend` folder:

```powershell
pytest tests
```

The tests do not need the server running. They create their own database and reset it with the demo data.

**Important:** the tests use the same `vapt.db` file as the running server, so running them replaces the dashboard data. Click **Reset & Load Seed Demo Data** afterwards to restore the demo.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `503 Service Unavailable` on seed, upload, or fix | `API_KEY` not loaded | Create `.env` in the repo root with `API_KEY=...`, then restart the backend |
| `NOT NULL constraint failed: vulnerability_history.cve_id` | Old database file with a previous schema | Stop the server, delete `backend/vapt.db`, restart |
| `'return' outside function` on startup | Partial edit left a `return` outside its function | Replace the whole function, then restart |
| Dashboard shows "Error seeding data" | Backend not running, or the error above | Check the uvicorn terminal for the traceback |
| Tier Agreement shows N/A | Model file missing | Run `python ml/train_model.py`, or accept the heuristic fallback |
| Why? button missing | Explainability not returned | Ensure the list endpoint uses `include_explainability=True` |

---

## Limitations

- **Synthetic training labels.** The model learns a documented formula with noise. It shows the pipeline can learn multi-factor weighting. It does not show real-world breach prediction.
- **Tier agreement is not accuracy.** It measures agreement with synthetic labels.
- **Explanations are formula-based.** Per-factor breakdowns come from the scoring formula, not from the model's internals.
- **Scanner formats.** Only JSON in the shape above is accepted. XML and native scanner exports must be converted first.
- **No live scanning.** The system ingests and scores findings. It does not run scans or connect to scanners.
- **Demo-grade security.** A single shared API key and permissive CORS are suitable for local demos only.
- **SQLite by default.** Suitable for a single-user demo. Use PostgreSQL for shared deployments.

---

## Licence and Attribution

Built as an academic project. Demo assets, scan data, and the training dataset are synthetic and do not describe any real organisation.