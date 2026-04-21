from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import DetectionJob, DetectionJobStatus, Event
from app.services.detection_service import detect_event, persist_detections_and_alerts


def enqueue_detection_job(db: Session, *, organization_id: int, event_id: int) -> DetectionJob:
    job = DetectionJob(
        organization_id=organization_id,
        event_id=event_id,
        status=DetectionJobStatus.queued,
    )
    db.add(job)
    db.flush()
    return job


def process_detection_job(db: Session, job: DetectionJob) -> tuple[int, int]:
    event = db.query(Event).filter(Event.id == job.event_id, Event.organization_id == job.organization_id).first()
    if not event:
        job.status = DetectionJobStatus.failed
        job.error_message = "Event not found"
        job.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.flush()
        return 0, 0

    job.status = DetectionJobStatus.processing
    job.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.flush()

    try:
        signals = detect_event(db, event)
        detections, alerts = persist_detections_and_alerts(db, event, signals)
        job.status = DetectionJobStatus.completed
        job.detections_generated = len(detections)
        job.alerts_generated = len(alerts)
        job.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        job.error_message = None
        db.flush()
        return len(detections), len(alerts)
    except Exception as exc:  # defensive job tracking
        job.status = DetectionJobStatus.failed
        job.error_message = str(exc)
        job.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.flush()
        raise


def process_pending_jobs(db: Session, *, organization_id: int, limit: int = 100) -> list[DetectionJob]:
    jobs = (
        db.query(DetectionJob)
        .filter(
            DetectionJob.organization_id == organization_id,
            DetectionJob.status == DetectionJobStatus.queued,
        )
        .order_by(DetectionJob.created_at.asc())
        .limit(min(max(limit, 1), 500))
        .all()
    )
    for job in jobs:
        process_detection_job(db, job)
    db.flush()
    return jobs
