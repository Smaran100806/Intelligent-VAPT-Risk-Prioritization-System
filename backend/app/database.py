"""
database.py — Database engine and session management.

Supports SQLite for local development and PostgreSQL for production
via the DATABASE_URL environment variable.
"""

import logging
import os

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from app.env import load_local_env

load_local_env()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Settings (replace with pydantic-settings in milestone 2)
# ---------------------------------------------------------------------------

DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./vapt.db")

# SQLite requires check_same_thread=False for FastAPI's async usage
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

# ---------------------------------------------------------------------------
# Engine & session factory
# ---------------------------------------------------------------------------

engine = create_engine(
    DATABASE_URL,
    connect_args=_connect_args,
    echo=False,  # set True for SQL query logging during development
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ---------------------------------------------------------------------------
# Declarative base (shared by all ORM models)
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Dependency — yields a DB session per request
# ---------------------------------------------------------------------------

def get_db():
    """
    FastAPI dependency that provides a SQLAlchemy session.
    Usage:
        @router.get("/items")
        def list_items(db: Session = Depends(get_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Table creation helper (called from main.py on startup for dev mode)
# ---------------------------------------------------------------------------

def create_tables() -> None:
    """Create all tables defined in ORM models. For production, use Alembic."""
    # Import models here so Base.metadata is populated before create_all
    from app import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_columns()


def _ensure_sqlite_columns() -> None:
    """Add columns introduced after the first SQLite file was created."""
    if not str(engine.url).startswith("sqlite"):
        return
    with engine.begin() as conn:
        tables = {
            row[0]
            for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
        }
        if "vulnerabilities" in tables:
            vuln_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(vulnerabilities)"))}
            if "model_used" not in vuln_cols:
                conn.execute(text("ALTER TABLE vulnerabilities ADD COLUMN model_used VARCHAR(32)"))
        if "vulnerability_history" in tables:
            hist_cols = {row[1] for row in conn.execute(text("PRAGMA table_info(vulnerability_history)"))}
            if "finding_key" not in hist_cols:
                conn.execute(text("ALTER TABLE vulnerability_history ADD COLUMN finding_key VARCHAR(256)"))
        if "assets" in tables:
            try:
                conn.execute(
                    text(
                        "CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_ip_address "
                        "ON assets(ip_address) WHERE ip_address IS NOT NULL"
                    )
                )
            except Exception as exc:
                logger.warning("Could not enforce unique asset IP addresses: %s", exc)
