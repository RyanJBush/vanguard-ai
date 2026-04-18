from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Event, User
from app.schemas import EventCreate, EventIngestResponse, EventOut
from app.services.detection_service import (
    default_occurred_at,
    detect_event,
    persist_detections_and_alerts,
)

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("", response_model=EventIngestResponse)
def create_event(
    payload: EventCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    event = Event(
        organization_id=current_user.organization_id,
        source=payload.source,
        source_ip=payload.source_ip,
        username=payload.username,
        event_type=payload.event_type,
        severity=payload.severity,
        status=payload.status,
        message=payload.message,
        event_metadata=payload.metadata,
        occurred_at=default_occurred_at(payload.occurred_at),
    )
    db.add(event)
    db.flush()

    signals = detect_event(db, event)
    detections, alerts = persist_detections_and_alerts(db, event, signals)
    db.commit()
    db.refresh(event)

    return {"event": event, "detections": detections, "alerts": alerts}


@router.get("", response_model=list[EventOut])
def list_events(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(Event)
        .filter(Event.organization_id == current_user.organization_id)
        .order_by(Event.occurred_at.desc())
        .limit(limit)
        .all()
    )


@router.get("/{event_id}", response_model=EventOut)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    event = (
        db.query(Event)
        .filter(Event.id == event_id, Event.organization_id == current_user.organization_id)
        .first()
    )
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
