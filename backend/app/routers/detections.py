from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Detection, User
from app.schemas import DetectionOut

router = APIRouter(prefix="/api/detections", tags=["detections"])


@router.get("", response_model=list[DetectionOut])
def list_detections(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (
        db.query(Detection)
        .filter(Detection.organization_id == current_user.organization_id)
        .order_by(Detection.created_at.desc())
        .all()
    )
