from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Alert, AlertStatus, InvestigationNote, UserRole
from app.schemas.alerts import (
    AlertResponse,
    AlertStatusUpdate,
    InvestigationNoteCreate,
    InvestigationNoteResponse,
)
from app.models import Alert, AlertStatus, UserRole
from app.schemas.alerts import AlertResponse, AlertStatusUpdate
from app.schemas.auth import UserContext
from app.services.dependencies import get_current_user_context, require_roles

router = APIRouter(prefix="/alerts")


@router.get("", response_model=list[AlertResponse])
def list_alerts(
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user_context),
) -> list[AlertResponse]:
    alerts = (
        db.query(Alert)
        .filter(Alert.organization_id == current_user.organization_id)
        .order_by(Alert.created_at.desc())
        .limit(100)
        .all()
    )
    return [AlertResponse.model_validate(alert) for alert in alerts]


@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user_context),
) -> AlertResponse:
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.organization_id == current_user.organization_id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(require_roles(UserRole.admin, UserRole.analyst)),
) -> AlertResponse:
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.organization_id == current_user.organization_id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    try:
        alert.status = AlertStatus(payload.status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid status") from exc

    db.commit()
    db.refresh(alert)
    return AlertResponse.model_validate(alert)


@router.get("/{alert_id}/notes", response_model=list[InvestigationNoteResponse])
def list_notes(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user_context),
) -> list[InvestigationNoteResponse]:
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.organization_id == current_user.organization_id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    notes = db.query(InvestigationNote).filter(InvestigationNote.alert_id == alert_id).all()
    return [InvestigationNoteResponse.model_validate(note) for note in notes]


@router.post("/{alert_id}/notes", response_model=InvestigationNoteResponse)
def create_note(
    alert_id: int,
    payload: InvestigationNoteCreate,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(require_roles(UserRole.admin, UserRole.analyst)),
) -> InvestigationNoteResponse:
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id, Alert.organization_id == current_user.organization_id)
        .first()
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    note = InvestigationNote(alert_id=alert_id, author_id=current_user.id, note=payload.note)
    db.add(note)
    db.commit()
    db.refresh(note)
    return InvestigationNoteResponse.model_validate(note)
