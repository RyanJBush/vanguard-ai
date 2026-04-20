from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user, require_roles
from app.models import Alert, AlertStatus, InvestigationNote, Role, User
from app.schemas import (
    AlertOut,
    AlertStatusUpdate,
    InvestigationNoteCreate,
    InvestigationNoteOut,
)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    status: AlertStatus | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Alert).filter(Alert.organization_id == current_user.organization_id)
    if status:
        query = query.filter(Alert.status == status)
    return query.order_by(Alert.created_at.desc()).all()


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.organization_id == current_user.organization_id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/status", response_model=AlertOut)
def patch_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.analyst)),
):
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.organization_id == current_user.organization_id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = payload.status
    if payload.status == AlertStatus.closed:
        alert.closed_at = datetime.now(UTC).replace(tzinfo=None)
    else:
        alert.closed_at = None
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/{alert_id}/notes", response_model=list[InvestigationNoteOut])
def list_alert_notes(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.organization_id == current_user.organization_id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return (
        db.query(InvestigationNote)
        .filter(InvestigationNote.alert_id == alert_id)
        .order_by(InvestigationNote.created_at.desc())
        .all()
    )


@router.post("/{alert_id}/notes", response_model=InvestigationNoteOut)
def create_alert_note(
    alert_id: int,
    payload: InvestigationNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.analyst)),
):
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.organization_id == current_user.organization_id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    note = InvestigationNote(
        alert_id=alert.id,
        author_id=current_user.id,
        note=payload.note.strip(),
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note
