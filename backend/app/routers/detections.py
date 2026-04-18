from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Detection, Event
from app.schemas.auth import UserContext
from app.schemas.detections import DetectionResponse
from app.services.dependencies import get_current_user_context

router = APIRouter(prefix="/detections")


@router.get("", response_model=list[DetectionResponse])
def list_detections(
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user_context),
) -> list[DetectionResponse]:
    detections = (
        db.query(Detection)
        .join(Event, Detection.event_id == Event.id)
        .filter(Event.organization_id == current_user.organization_id)
        .order_by(Detection.created_at.desc())
        .limit(100)
        .all()
    )
    return [DetectionResponse.model_validate(detection) for detection in detections]
