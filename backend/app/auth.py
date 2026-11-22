"""
auth.py — Header authentication for write endpoints.

The expected keys live only in the server environment. The dashboard dev server
injects X-API-Key while proxying, so the browser bundle does not contain it.
"""

from __future__ import annotations

import os
import secrets
from typing import Optional

from fastapi import Header, HTTPException, status

from app.env import load_local_env

load_local_env()


def _keys_match(provided: Optional[str], expected: str) -> bool:
    if not provided:
        return False
    try:
        return secrets.compare_digest(
            provided.encode("utf-8"),
            expected.encode("utf-8"),
        )
    except (TypeError, ValueError):
        return False


def verify_api_key(x_api_key: Optional[str] = Header(None)) -> bool:
    """Validate X-API-Key against the API_KEY environment variable."""
    expected = os.getenv("API_KEY", "").strip()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Server API_KEY is not configured",
        )
    if not _keys_match(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key authentication header",
        )
    return True


def verify_seed_access(
    x_api_key: Optional[str] = Header(None),
    x_admin_key: Optional[str] = Header(None),
) -> bool:
    """
    Seed wipes and reloads demo data.

    Development accepts the normal API key.
    Production refuses unless VAPT_ALLOW_SEED is set and X-Admin-Key matches ADMIN_API_KEY.
    """
    env = os.getenv("VAPT_ENV", "development").strip().lower()
    allow = os.getenv("VAPT_ALLOW_SEED", "").strip().lower() in {"1", "true", "yes"}
    admin = os.getenv("ADMIN_API_KEY", "").strip()

    if env == "production":
        if not allow:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Seed is disabled when VAPT_ENV=production. Set VAPT_ALLOW_SEED=true to override.",
            )
        if not admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Seed in production requires ADMIN_API_KEY and the X-Admin-Key header.",
            )

    if admin:
        if not _keys_match(x_admin_key, admin):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Seed requires a valid X-Admin-Key",
            )
        return True

    return verify_api_key(x_api_key)
