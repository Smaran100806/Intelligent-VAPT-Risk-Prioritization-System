"""
auth.py — Security dependencies & API key authentication.
"""

from __future__ import annotations

import os
from typing import Optional

from fastapi import Header, HTTPException, status

DEFAULT_API_KEY = "vapt-secure-api-key-2026"


def verify_api_key(x_api_key: Optional[str] = Header(None)) -> bool:
    """Validate X-API-Key header against API_KEY environment variable."""
    expected = os.getenv("API_KEY", DEFAULT_API_KEY)
    if not x_api_key or x_api_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key authentication header",
        )
    return True
