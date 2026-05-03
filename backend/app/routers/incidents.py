from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user, require_roles
from app.models import Alert, AlertTimelineEntry, AuditLog, Incident, IncidentStatus, Role, User
from app.schemas import (
    AiSummaryOut,
    IncidentAlertLinkRequest,
    IncidentCreate,
    IncidentListResponse,
    IncidentOut,
    IncidentStatusUpdate,
    IncidentTimelineEntryOut,
    PaginationMeta,
)
from app.services.ai_assistant import build_incident_wrapup
from app.services.audit import write_audit_log
from app.services.pagination import paginate_query

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _link_alerts_to_incident(
    db: Session,
    *,
    alert_ids: list[int],
    incident_id: int,
    organization_id: int,
    actor_id: int,
    assigned_analyst_id: int | None = None,
) -> int:
    alerts = (
        db.query(Alert)
        .filter(
            Alert.id.in_(alert_ids),
            Alert.organization_id == organization_id,
        )
        .all()
    )
    if len(alerts) != len(set(alert_ids)):
        raise HTTPException(status_code=400, detail="One or more alerts were not found")

    for alert in alerts:
        alert.incident_id = incident_id
        if assigned_analyst_id and not alert.assigned_analyst_id:
            alert.assigned_analyst_id = assigned_analyst_id
        db.add(
            AlertTimelineEntry(
                alert_id=alert.id,
                actor_id=actor_id,
                action="incident_linked",
                details=f"Alert linked to incident {incident_id}",
            )
        )
    return len(alerts)


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    status: IncidentStatus | None = None,
    page: int = 1,
    page_size: int = 50,
    sort_order: str = "desc",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Incident).filter(Incident.organization_id == current_user.organization_id)
    if status:
        query = query.filter(Incident.status == status)
    query = query.order_by(Incident.created_at.asc() if sort_order == "asc" else Incident.created_at.desc())
    items, total, safe_page, safe_page_size = paginate_query(query, page=page, page_size=page_size)
    return IncidentListResponse(
        items=items,
        pagination=PaginationMeta(page=safe_page, page_size=safe_page_size, total=total),
    )


@router.post("", response_model=IncidentOut)
def create_incident(
    payload: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.analyst)),
):
    incident = Incident(
        organization_id=current_user.organization_id,
        title=payload.title.strip(),
        summary=payload.summary.strip(),
        created_by_id=current_user.id,
        assigned_analyst_id=payload.assigned_analyst_id,
    )
    db.add(incident)
    db.flush()

    linked_count = 0
    if payload.alert_ids:
        linked_count = _link_alerts_to_incident(
            db,
            alert_ids=payload.alert_ids,
            incident_id=incident.id,
            organization_id=current_user.organization_id,
            actor_id=current_user.id,
            assigned_analyst_id=incident.assigned_analyst_id,
        )

    write_audit_log(
        db,
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="incident_created",
        target_type="incident",
        target_id=incident.id,
        details=f"alerts_linked={linked_count}",
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def patch_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.analyst)),
):
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = payload.status
    if payload.status == IncidentStatus.closed:
        incident.closed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    else:
        incident.closed_at = None

    write_audit_log(
        db,
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="incident_status_updated",
        target_type="incident",
        target_id=incident.id,
        details=f"status={payload.status.value}",
    )

    db.commit()
    db.refresh(incident)
    return incident


@router.get("/{incident_id}/ai-wrapup", response_model=AiSummaryOut)
def incident_ai_wrapup(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return AiSummaryOut(summary=build_incident_wrapup(incident))


@router.post("/{incident_id}/alerts", response_model=IncidentOut)
def add_alerts_to_incident(
    incident_id: int,
    payload: IncidentAlertLinkRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.analyst)),
):
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    linked_count = _link_alerts_to_incident(
        db,
        alert_ids=payload.alert_ids,
        incident_id=incident.id,
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        assigned_analyst_id=incident.assigned_analyst_id,
    )
    write_audit_log(
        db,
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="incident_alerts_linked",
        target_type="incident",
        target_id=incident.id,
        details=f"alerts_linked={linked_count}",
    )
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/{incident_id}/timeline", response_model=list[IncidentTimelineEntryOut])
def get_incident_timeline(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.organization_id == current_user.organization_id)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return (
        db.query(AuditLog)
        .filter(
            AuditLog.organization_id == current_user.organization_id,
            AuditLog.target_type == "incident",
            AuditLog.target_id == incident_id,
        )
        .order_by(AuditLog.created_at.desc())
        .all()
    )
