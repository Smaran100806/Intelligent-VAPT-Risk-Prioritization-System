"""
env.py — Load a local .env without overriding variables already set in the process.
"""

from __future__ import annotations

import os
from pathlib import Path

_LOADED = False


def load_local_env() -> None:
    """Read repo-root and backend .env files. Existing os.environ values win."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True

    root = Path(__file__).resolve().parents[2]
    for path in (root / ".env", root / "backend" / ".env"):
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                os.environ.setdefault(key, value)
