"""
database.py — Database engine and session management.

Supports SQLite for local development and PostgreSQL for production
via the DATABASE_URL environment variable.
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

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
