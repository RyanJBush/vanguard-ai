from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Alert, AlertStatus, Detection, Event
from app.schemas.metrics import SummaryMetrics


class MetricsService:
    def get_summary(self, db: Session, organization_id: int) -> SummaryMetrics:
        since = datetime.utcnow() - timedelta(hours=24)
        events_24h = (
            db.query(func.count(Event.id))
            .filter(Event.organization_id == organization_id, Event.occurred_at >= since)
            .scalar()
        )
        detections_24h = (
            db.query(func.count(Detection.id))
            .join(Event, Detection.event_id == Event.id)
            .filter(Event.organization_id == organization_id, Event.occurred_at >= since)
            .scalar()
        )
        alerts_open = (
            db.query(func.count(Alert.id))
            .filter(Alert.organization_id == organization_id, Alert.status == AlertStatus.open)
            .scalar()
        )
        alerts_investigating = (
            db.query(func.count(Alert.id))
            .filter(Alert.organization_id == organization_id, Alert.status == AlertStatus.investigating)
            .scalar()
        )
        alerts_resolved = (
            db.query(func.count(Alert.id))
            .filter(Alert.organization_id == organization_id, Alert.status == AlertStatus.resolved)
            .scalar()
        )

        return SummaryMetrics(
            events_24h=events_24h or 0,
            detections_24h=detections_24h or 0,
            alerts_open=alerts_open or 0,
            alerts_investigating=alerts_investigating or 0,
            alerts_resolved=alerts_resolved or 0,
        )


metrics_service = MetricsService()
