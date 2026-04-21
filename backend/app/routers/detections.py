from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Detection, User
from app.schemas import DetectionCatalogEntryOut, DetectionOut
from app.services.detection_catalog import list_detection_definitions

router = APIRouter(prefix="/api/detections", tags=["detections"])


@router.get("/catalog", response_model=list[DetectionCatalogEntryOut])
def list_detection_catalog(_: User = Depends(get_current_user)):
    return [
        DetectionCatalogEntryOut(
            key=item.key,
            title=item.title,
            severity=item.severity,
            default_confidence=item.default_confidence,
            mitre_techniques=list(item.mitre_techniques),
            mitre_tactics=list(item.mitre_tactics),
            recommendation=item.recommendation,
            description=item.description,
            dedup_window_minutes=item.dedup_window_minutes,
        )
        for item in list_detection_definitions()
    ]


@router.get("", response_model=list[DetectionOut])
def list_detections(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return (
        db.query(Detection)
        .filter(Detection.organization_id == current_user.organization_id)
        .order_by(Detection.created_at.desc())
        .all()
    )
