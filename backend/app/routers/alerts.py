from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user, require_roles
from app.models import Alert, AlertStatus, AlertTimelineEntry, AnalystFeedback, InvestigationNote, Role, User
from app.schemas import (
    AiSummaryOut,
    AiTriageOut,
    AlertAssignRequest,
    AlertListResponse,
    AlertOut,
    AlertStatusUpdate,
    AlertTimelineEntryOut,
    AnalystFeedbackCreate,
    AnalystFeedbackOut,
    InvestigationNoteCreate,
    InvestigationNoteOut,
    PaginationMeta,
)
from app.services.ai_assistant import build_alert_summary, build_triage_recommendation
from app.services.audit import write_audit_log
from app.services.pagination import paginate_query

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _get_alert_or_404(db: Session, alert_id: int, organization_id: int) -> Alert:
    alert = db.query(Alert).filter(Alert.id == alert_id, Alert.organization_id == organization_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


def _append_timeline(
    db: Session,
    *,
    alert_id: int,
    actor_id: int | None,
    action: str,
    details: str,
) -> None:
    db.add(
        AlertTimelineEntry(
            alert_id=alert_id,
            actor_id=actor_id,
            action=action,
            details=details,
        )
    )


@router.get("", response_model=AlertListResponse)
def list_alerts(
    status: AlertStatus | None = None,
    severity: str | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_by: str = "created_at",
    sort_order: str = "desc",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Alert).filter(Alert.organization_id == current_user.organization_id)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)

    sort_column = Alert.last_seen_at if sort_by == "last_seen_at" else Alert.created_at
    query = query.order_by(sort_column.asc() if sort_order == "asc" else sort_column.desc())
    items, total, safe_page, safe_page_size = paginate_query(query, page=page, page_size=page_size)
    return AlertListResponse(
        items=items,
        pagination=PaginationMeta(page=safe_page, page_size=safe_page_size, total=total),
    )


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return _get_alert_or_404(db, alert_id, current_user.organization_id)


@router.patch("/{alert_id}/status", response_model=AlertOut)
def patch_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.analyst)),
):
    alert = _get_alert_or_404(db, alert_id, current_user.organization_id)
    previous_status = alert.status
    alert.status = payload.status
    if payload.status == AlertStatus.closed:
        alert.closed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    else:
        alert.closed_at = None

    _append_timeline(
        db,
        alert_id=alert.id,
        actor_id=current_user.id,
        action="status_updated",
        details=f"Status changed from {previous_status.value} to {payload.status.value}",
    )
    write_audit_log(
        db,
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="alert_status_updated",
        target_type="alert",
        target_id=alert.id,
        details=f"{previous_status.value}->{payload.status.value}",
    )
    db.commit()
    db.refresh(alert)
    return alert


@router.patch("/{alert_id}/assign", response_model=AlertOut)
def assign_alert(
    alert_id: int,
    payload: AlertAssignRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.analyst)),
):
    alert = _get_alert_or_404(db, alert_id, current_user.organization_id)
    if payload.analyst_id is not None:
        assignee = (
            db.query(User)
            .filter(
                User.id == payload.analyst_id,
                User.organization_id == current_user.organization_id,
                User.role.in_([Role.analyst, Role.admin]),
            )
            .first()
        )
        if not assignee:
            raise HTTPException(status_code=400, detail="Assigned analyst must be an Admin or Analyst")
    alert.assigned_analyst_id = payload.analyst_id
    _append_timeline(
        db,
        alert_id=alert.id,
        actor_id=current_user.id,
        action="analyst_assigned",
        details=f"Assigned analyst set to {payload.analyst_id}",
    )
    write_audit_log(
        db,
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="alert_assigned",
        target_type="alert",
        target_id=alert.id,
        details=f"assigned_analyst_id={payload.analyst_id}",
    )
    db.commit()
    db.refresh(alert)
    return alert


@router.get("/{alert_id}/notes", response_model=list[InvestigationNoteOut])
def list_alert_notes(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _get_alert_or_404(db, alert_id, current_user.organization_id)
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
    alert = _get_alert_or_404(db, alert_id, current_user.organization_id)

    note = InvestigationNote(
        alert_id=alert.id,
        author_id=current_user.id,
        note=payload.note.strip(),
    )
    db.add(note)
    _append_timeline(
        db,
        alert_id=alert.id,
        actor_id=current_user.id,
        action="note_added",
        details=payload.note.strip(),
    )
    write_audit_log(
        db,
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="alert_note_added",
        target_type="alert",
        target_id=alert.id,
        details=payload.note.strip(),
    )
    db.commit()
    db.refresh(note)
    return note


@router.get("/{alert_id}/timeline", response_model=list[AlertTimelineEntryOut])
def list_alert_timeline(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _get_alert_or_404(db, alert_id, current_user.organization_id)
    return (
        db.query(AlertTimelineEntry)
        .filter(AlertTimelineEntry.alert_id == alert_id)
        .order_by(AlertTimelineEntry.created_at.desc())
        .all()
    )


@router.post("/{alert_id}/feedback", response_model=AnalystFeedbackOut)
def create_alert_feedback(
    alert_id: int,
    payload: AnalystFeedbackCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.analyst)),
):
    alert = _get_alert_or_404(db, alert_id, current_user.organization_id)
    feedback = AnalystFeedback(
        organization_id=current_user.organization_id,
        alert_id=alert.id,
        analyst_id=current_user.id,
        is_true_positive=payload.is_true_positive,
        tuning_notes=payload.tuning_notes.strip(),
    )
    db.add(feedback)
    write_audit_log(
        db,
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="analyst_feedback_submitted",
        target_type="alert",
        target_id=alert.id,
        details=f"true_positive={payload.is_true_positive}",
    )
    db.commit()
    db.refresh(feedback)
    return feedback


@router.get("/{alert_id}/ai-summary", response_model=AiSummaryOut)
def get_alert_ai_summary(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = _get_alert_or_404(db, alert_id, current_user.organization_id)
    return AiSummaryOut(summary=build_alert_summary(alert))


@router.get("/{alert_id}/ai-triage", response_model=AiTriageOut)
def get_alert_ai_triage(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = _get_alert_or_404(db, alert_id, current_user.organization_id)
    recommendation, priority = build_triage_recommendation(alert)
    return AiTriageOut(recommendation=recommendation, priority=priority)
