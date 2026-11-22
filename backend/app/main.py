"""
main.py — FastAPI application entry point.

Registers routers, middleware, and startup/shutdown events.
Application logic to be implemented in subsequent milestones.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ---------------------------------------------------------------------------
# App instance
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Intelligent VAPT Risk Prioritization System",
    description="AI-powered vulnerability triage and risk scoring API.",
    version="0.1.0",
)

# ---------------------------------------------------------------------------
# CORS — tighten origins for production
# ---------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers (to be uncommented as implemented)
# ---------------------------------------------------------------------------

# from app.routers import vulnerabilities, assets, auth, reports
# app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
# app.include_router(assets.router, prefix="/api/assets", tags=["assets"])
# app.include_router(vulnerabilities.router, prefix="/api/vulns", tags=["vulnerabilities"])
# app.include_router(reports.router, prefix="/api/reports", tags=["reports"])

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
async def health_check() -> dict:
    """Liveness probe endpoint."""
    return {"status": "ok", "version": app.version}


@app.get("/", tags=["meta"])
async def root() -> dict:
    return {"message": "VAPT Risk Prioritization API — see /docs for Swagger UI"}
