import logging

from sqlalchemy.orm import Session

from app.models import Alert, Detection, Event
from app.schemas.events import EventIngestRequest
from app.services.detection_engine import detection_engine

logger = logging.getLogger(__name__)


class IngestionService:
    def ingest_event(self, db: Session, organization_id: int, event_in: EventIngestRequest) -> Event:
        event = Event(
            organization_id=organization_id,
            event_type=event_in.event_type,
            source_ip=event_in.source_ip,
            actor=event_in.actor,
            severity=event_in.severity,
            occurred_at=event_in.occurred_at,
            payload=event_in.payload,
        )
        db.add(event)
        db.flush()

        findings = detection_engine.evaluate_event(event)
        for finding in findings:
            detection = Detection(
                event_id=event.id,
                rule_name=finding.rule_name,
                confidence=finding.confidence,
                details={"description": finding.description},
            )
            db.add(detection)
            db.flush()

            alert = Alert(
                organization_id=organization_id,
                event_id=event.id,
                detection_id=detection.id,
                title=f"Detection: {finding.rule_name}",
                description=finding.description,
                severity=finding.severity,
            )
            db.add(alert)

        db.commit()
        db.refresh(event)
        logger.info("event_ingested", extra={"context": {"event_id": event.id, "findings": len(findings)}})
        return event


ingestion_service = IngestionService()
