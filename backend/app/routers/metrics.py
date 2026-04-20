from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Alert, AlertStatus, Event, InvestigationNote, User
from app.schemas import MetricsSummary

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


@router.get("/summary", response_model=MetricsSummary)
def summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total_events = (
        db.query(func.count(Event.id))
        .filter(Event.organization_id == current_user.organization_id)
        .scalar()
    )
    total_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.organization_id == current_user.organization_id)
        .scalar()
    )
    open_alerts = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.organization_id == current_user.organization_id,
            Alert.status.in_(
                [
                    AlertStatus.open,
                    AlertStatus.triaged,
                    AlertStatus.investigating,
                    AlertStatus.escalated,
                ]
            ),
        )
        .scalar()
    )
    high_severity_alerts = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.organization_id == current_user.organization_id,
            Alert.severity.in_(["high", "critical"]),
        )
        .scalar()
    )
    triaged_alerts = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.organization_id == current_user.organization_id,
            Alert.status == AlertStatus.triaged,
        )
        .scalar()
    )
    investigating_alerts = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.organization_id == current_user.organization_id,
            Alert.status == AlertStatus.investigating,
        )
        .scalar()
    )
    escalated_alerts = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.organization_id == current_user.organization_id,
            Alert.status == AlertStatus.escalated,
        )
        .scalar()
    )
    closed_alerts = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.organization_id == current_user.organization_id,
            Alert.status == AlertStatus.closed,
        )
        .scalar()
    )
    detection_events = (
        db.query(func.count(func.distinct(Alert.event_id)))
        .filter(Alert.organization_id == current_user.organization_id)
        .scalar()
    )
    detection_pairs = (
        db.query(Alert.created_at, Event.occurred_at)
        .join(Event, Event.id == Alert.event_id)
        .filter(Alert.organization_id == current_user.organization_id)
        .all()
    )
    resolution_pairs = (
        db.query(Alert.created_at, Alert.closed_at)
        .filter(
            Alert.organization_id == current_user.organization_id,
            Alert.status == AlertStatus.closed,
            Alert.closed_at.is_not(None),
        )
        .all()
    )
    coverage = (float(detection_events) / float(total_events) * 100.0) if total_events else 0.0
    closed_alert_ids = [
        alert_id
        for (alert_id,) in (
            db.query(Alert.id)
            .filter(
                Alert.organization_id == current_user.organization_id,
                Alert.status == AlertStatus.closed,
            )
            .all()
        )
    ]
    false_positive_alert_ids = (
        {
            alert_id
            for (alert_id,) in (
                db.query(InvestigationNote.alert_id)
                .filter(
                    InvestigationNote.alert_id.in_(closed_alert_ids),
                    InvestigationNote.note.ilike("%false positive%"),
                )
                .all()
            )
        }
        if closed_alert_ids
        else set()
    )
    false_positive_count = min(len(false_positive_alert_ids), int(closed_alerts))
    false_positive_rate = (
        round((false_positive_count / float(closed_alerts)) * 100.0, 2)
        if closed_alerts
        else 0.0
    )
    avg_detection_latency_seconds = (
        sum(
            (created_at - occurred_at).total_seconds()
            for created_at, occurred_at in detection_pairs
        )
        / len(detection_pairs)
        if detection_pairs
        else 0.0
    )
    avg_resolution_seconds = (
        sum((closed_at - created_at).total_seconds() for created_at, closed_at in resolution_pairs)
        / len(resolution_pairs)
        if resolution_pairs
        else 0.0
    )

    return MetricsSummary(
        total_events=total_events,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        high_severity_alerts=high_severity_alerts,
        triaged_alerts=triaged_alerts,
        investigating_alerts=investigating_alerts,
        escalated_alerts=escalated_alerts,
        closed_alerts=closed_alerts,
        mttd_minutes=round(float(avg_detection_latency_seconds) / 60.0, 2),
        mttr_minutes=round(float(avg_resolution_seconds) / 60.0, 2),
        false_positive_rate=false_positive_rate,
        detection_coverage=round(coverage, 2),
    )
