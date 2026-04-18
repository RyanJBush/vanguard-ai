from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Event, UserRole
from app.schemas.auth import UserContext
from app.schemas.events import EventIngestRequest, EventResponse
from app.services.dependencies import get_current_user_context, require_roles
from app.services.ingestion_service import ingestion_service

router = APIRouter(prefix="/events")


@router.post("", response_model=EventResponse)
def ingest_event(
    payload: EventIngestRequest,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(require_roles(UserRole.admin, UserRole.analyst)),
) -> EventResponse:
    event = ingestion_service.ingest_event(db, current_user.organization_id, payload)
    return EventResponse.model_validate(event)


@router.get("", response_model=list[EventResponse])
def list_events(
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user_context),
) -> list[EventResponse]:
    events = (
        db.query(Event)
        .filter(Event.organization_id == current_user.organization_id)
        .order_by(Event.occurred_at.desc())
        .limit(100)
        .all()
    )
    return [EventResponse.model_validate(event) for event in events]
