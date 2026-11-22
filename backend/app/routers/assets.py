"""
routers/assets.py — Asset management endpoints.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import verify_api_key
from app.database import get_db
from app.models import Asset
from app.schemas import AssetCreate, AssetResponse

router = APIRouter()


def _asset_or_404(asset_id: int, db: Session) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return asset


@router.get("", response_model=List[AssetResponse])
def list_assets(
    exposure: Optional[str] = None,
    asset_type: Optional[str] = None,
    db: Session = Depends(get_db),
):
    stmt = select(Asset)
    if exposure:
        stmt = stmt.where(Asset.exposure == exposure)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    stmt = stmt.order_by(Asset.criticality.desc(), Asset.id.asc())
    return db.execute(stmt).scalars().all()


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_api_key),
):
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    return _asset_or_404(asset_id, db)


@router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    payload: AssetCreate,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_api_key),
):
    asset = _asset_or_404(asset_id, db)
    for field, val in payload.model_dump().items():
        setattr(asset, field, val)
    db.commit()
    db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    _auth: bool = Depends(verify_api_key),
):
    asset = _asset_or_404(asset_id, db)
    db.delete(asset)
    db.commit()
    return None
