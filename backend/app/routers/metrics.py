from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user
from app.models import (
    Alert,
    AlertStatus,
    AnalystFeedback,
    Detection,
    DetectionJob,
    DetectionJobStatus,
    Event,
    InvestigationNote,
    User,
)
from app.schemas import (
    DetectionComparisonOut,
    CorrelationHotspotOut,
    DetectionMethodMetrics,
    DetectionQualityOut,
    JobMetricsOut,
    KpiSummary,
    MetricsSummary,
    ScenarioBenchmarkOut,
)
from app.services.seed_scenarios import SCENARIO_DEFINITIONS

router = APIRouter(prefix="/api/metrics", tags=["metrics"])


def _build_metrics_summary(db: Session, organization_id: int) -> MetricsSummary:
    total_events = db.query(func.count(Event.id)).filter(Event.organization_id == organization_id).scalar()
    total_alerts = db.query(func.count(Alert.id)).filter(Alert.organization_id == organization_id).scalar()
    open_alerts = (
        db.query(func.count(Alert.id))
        .filter(
            Alert.organization_id == organization_id,
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
        .filter(Alert.organization_id == organization_id, Alert.severity.in_(["high", "critical"]))
        .scalar()
    )
    triaged_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.organization_id == organization_id, Alert.status == AlertStatus.triaged)
        .scalar()
    )
    investigating_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.organization_id == organization_id, Alert.status == AlertStatus.investigating)
        .scalar()
    )
    escalated_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.organization_id == organization_id, Alert.status == AlertStatus.escalated)
        .scalar()
    )
    closed_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.organization_id == organization_id, Alert.status == AlertStatus.closed)
        .scalar()
    )
    detection_events = (
        db.query(func.count(func.distinct(Alert.event_id))).filter(Alert.organization_id == organization_id).scalar()
    )
    detection_pairs = (
        db.query(Alert.created_at, Event.occurred_at)
        .join(Event, Event.id == Alert.event_id)
        .filter(Alert.organization_id == organization_id)
        .all()
    )
    resolution_pairs = (
        db.query(Alert.created_at, Alert.closed_at)
        .filter(
            Alert.organization_id == organization_id,
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
            .filter(Alert.organization_id == organization_id, Alert.status == AlertStatus.closed)
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
        round((false_positive_count / float(closed_alerts)) * 100.0, 2) if closed_alerts else 0.0
    )
    avg_detection_latency_seconds = (
        sum((created_at - occurred_at).total_seconds() for created_at, occurred_at in detection_pairs)
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


@router.get("/summary", response_model=MetricsSummary)
def summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return _build_metrics_summary(db=db, organization_id=current_user.organization_id)


@router.get("/kpis", response_model=KpiSummary)
def kpis(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    metrics = _build_metrics_summary(db=db, organization_id=current_user.organization_id)
    return KpiSummary(
        open_alerts=metrics.open_alerts,
        high_severity_alerts=metrics.high_severity_alerts,
        mttd_minutes=metrics.mttd_minutes,
        mttr_minutes=metrics.mttr_minutes,
        false_positive_rate=metrics.false_positive_rate,
    )


@router.get("/detection-comparison", response_model=DetectionComparisonOut)
def detection_comparison(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    per_method = (
        db.query(
            Detection.detection_method,
            func.count(Detection.id).label("detections"),
            func.avg(Detection.confidence_score).label("avg_confidence"),
        )
        .filter(Detection.organization_id == current_user.organization_id)
        .group_by(Detection.detection_method)
        .all()
    )
    alert_counts = (
        db.query(
            Detection.detection_method,
            func.count(Alert.id).label("alerts"),
        )
        .join(Alert, Alert.detection_id == Detection.id)
        .filter(Detection.organization_id == current_user.organization_id)
        .group_by(Detection.detection_method)
        .all()
    )
    alert_map = {method: alerts for method, alerts in alert_counts}

    methods = [
        DetectionMethodMetrics(
            method=method,
            detections=detections,
            alerts=alert_map.get(method, 0),
            avg_confidence=round(float(avg_confidence or 0.0), 3),
        )
        for method, detections, avg_confidence in per_method
    ]
    return DetectionComparisonOut(methods=methods)


@router.get("/jobs", response_model=JobMetricsOut)
def job_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    queued = (
        db.query(func.count(DetectionJob.id))
        .filter(
            DetectionJob.organization_id == current_user.organization_id,
            DetectionJob.status == DetectionJobStatus.queued,
        )
        .scalar()
    )
    processing = (
        db.query(func.count(DetectionJob.id))
        .filter(
            DetectionJob.organization_id == current_user.organization_id,
            DetectionJob.status == DetectionJobStatus.processing,
        )
        .scalar()
    )
    completed = (
        db.query(func.count(DetectionJob.id))
        .filter(
            DetectionJob.organization_id == current_user.organization_id,
            DetectionJob.status == DetectionJobStatus.completed,
        )
        .scalar()
    )
    failed = (
        db.query(func.count(DetectionJob.id))
        .filter(
            DetectionJob.organization_id == current_user.organization_id,
            DetectionJob.status == DetectionJobStatus.failed,
        )
        .scalar()
    )
    durations = (
        db.query(DetectionJob.started_at, DetectionJob.completed_at)
        .filter(
            DetectionJob.organization_id == current_user.organization_id,
            DetectionJob.status == DetectionJobStatus.completed,
            DetectionJob.started_at.is_not(None),
            DetectionJob.completed_at.is_not(None),
        )
        .all()
    )
    avg_duration = (
        sum((completed_at - started_at).total_seconds() for started_at, completed_at in durations)
        / len(durations)
        if durations
        else 0.0
    )
    return JobMetricsOut(
        queued=queued,
        processing=processing,
        completed=completed,
        failed=failed,
        avg_duration_seconds=round(float(avg_duration), 3),
    )


@router.get("/detection-quality", response_model=DetectionQualityOut)
def detection_quality(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    reviewed_alerts = (
        db.query(func.count(AnalystFeedback.id))
        .filter(AnalystFeedback.organization_id == current_user.organization_id)
        .scalar()
    )
    true_positives = (
        db.query(func.count(AnalystFeedback.id))
        .filter(
            AnalystFeedback.organization_id == current_user.organization_id,
            AnalystFeedback.is_true_positive.is_(True),
        )
        .scalar()
    )
    false_positives = max(int(reviewed_alerts) - int(true_positives), 0)
    precision = round((float(true_positives) / float(reviewed_alerts)) * 100.0, 2) if reviewed_alerts else 0.0
    fpr = (
        round((float(false_positives) / float(reviewed_alerts)) * 100.0, 2)
        if reviewed_alerts
        else 0.0
    )
    return DetectionQualityOut(
        reviewed_alerts=reviewed_alerts,
        true_positive_count=true_positives,
        false_positive_count=false_positives,
        precision=precision,
        false_positive_rate=fpr,
    )


@router.get("/scenario-benchmarks", response_model=list[ScenarioBenchmarkOut])
def scenario_benchmarks(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    results: list[ScenarioBenchmarkOut] = []
    for key, definition in SCENARIO_DEFINITIONS.items():
        rows = (
            db.query(Detection.detection_type, Event.event_metadata)
            .join(Event, Event.id == Detection.event_id)
            .filter(Detection.organization_id == current_user.organization_id)
            .all()
        )
        observed = {
            detection_type
            for detection_type, metadata in rows
            if isinstance(metadata, dict) and metadata.get("scenario") == key
        }
        expected = set(definition.expected_detections)
        coverage = round((len(observed & expected) / len(expected) * 100.0), 2) if expected else 0.0
        results.append(
            ScenarioBenchmarkOut(
                scenario=key,
                expected_detections=sorted(expected),
                observed_detections=sorted(observed),
                coverage_percent=coverage,
            )
        )
    return results


@router.get("/correlation-hotspots", response_model=list[CorrelationHotspotOut])
def correlation_hotspots(
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = (
        db.query(
            Alert.correlation_id,
            func.count(Alert.id).label("alert_count"),
            func.max(Alert.dedup_count).label("max_dedup_count"),
            func.avg(Alert.confidence_score).label("avg_confidence"),
        )
        .filter(Alert.organization_id == current_user.organization_id)
        .group_by(Alert.correlation_id)
        .order_by(func.max(Alert.dedup_count).desc(), func.count(Alert.id).desc())
        .limit(min(max(limit, 1), 50))
        .all()
    )
    return [
        CorrelationHotspotOut(
            correlation_id=correlation_id,
            alert_count=int(alert_count or 0),
            max_dedup_count=int(max_dedup_count or 0),
            avg_confidence=round(float(avg_confidence or 0.0), 3),
        )
        for correlation_id, alert_count, max_dedup_count, avg_confidence in rows
    ]
