from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import Alert, Event, User
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
        .filter(Alert.organization_id == current_user.organization_id, Alert.status == "open")
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
    detection_events = (
        db.query(func.count(func.distinct(Alert.event_id)))
        .filter(Alert.organization_id == current_user.organization_id)
        .scalar()
    )
    coverage = (float(detection_events) / float(total_events) * 100.0) if total_events else 0.0

    return MetricsSummary(
        total_events=total_events,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        high_severity_alerts=high_severity_alerts,
        detection_coverage=round(coverage, 2),
    )
