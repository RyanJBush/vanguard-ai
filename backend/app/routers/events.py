from datetime import datetime, timedelta, timezone
from time import sleep

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user, require_roles
from app.models import Event, Role, User
from app.schemas import (
    BatchEventIngestRequest,
    BatchEventIngestResponse,
    EventCreate,
    EventIngestResponse,
    EventListResponse,
    EventOut,
    PaginationMeta,
    RunSimulationResponse,
    ReplayEventsRequest,
    ReplayEventsResponse,
    SeedScenarioIngestResult,
    SeedScenarioOut,
    StreamEventIngestRequest,
)
from app.services.detection_service import (
    default_occurred_at,
)
from app.services.job_service import enqueue_detection_job, process_detection_job
from app.services.seed_scenarios import (
    SCENARIO_DEFINITIONS,
    build_scenario_events,
    list_seed_scenarios,
)
from app.services.pagination import paginate_query

router = APIRouter(prefix="/api/events", tags=["events"])


def _normalized_metadata(payload: EventCreate) -> dict:
    """Normalize ingestion shape into a SOC-friendly envelope without breaking existing fields."""
    metadata = dict(payload.metadata or {})
    metadata.setdefault("timestamp", default_occurred_at(payload.occurred_at).isoformat())
    metadata.setdefault("user_id", payload.username)
    metadata.setdefault("ip", payload.source_ip)
    metadata.setdefault("action", payload.event_type)
    metadata.setdefault("status", payload.status)

    # explicit event classes used by phase-2 replay/streaming workflows
    metadata.setdefault("log_type", metadata.get("log_type") or payload.source)
    return metadata


@router.post("", response_model=EventIngestResponse)
def create_event(
    payload: EventCreate,
    defer_detection: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    event = Event(
        organization_id=current_user.organization_id,
        source=payload.source,
        source_ip=payload.source_ip,
        username=payload.username,
        event_type=payload.event_type,
        severity=payload.severity,
        status=payload.status,
        message=payload.message,
        event_metadata=_normalized_metadata(payload),
        occurred_at=default_occurred_at(payload.occurred_at),
    )
    db.add(event)
    db.flush()

    job = enqueue_detection_job(
        db,
        organization_id=current_user.organization_id,
        event_id=event.id,
    )

    detections = []
    alerts = []
    if not defer_detection:
        process_detection_job(db, job)
        detections = list(event.detections)
        alerts = [detection.alert for detection in detections if detection.alert]
    db.commit()
    db.refresh(event)

    return {
        "event": event,
        "detections": detections,
        "alerts": alerts,
        "job_id": job.id,
    }


@router.post("/batch", response_model=BatchEventIngestResponse)
def create_events_batch(
    payload: BatchEventIngestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    detections_generated = 0
    alerts_generated = 0
    job_ids: list[int] = []

    for item in payload.events:
        event = Event(
            organization_id=current_user.organization_id,
            source=item.source,
            source_ip=item.source_ip,
            username=item.username,
            event_type=item.event_type,
            severity=item.severity,
            status=item.status,
            message=item.message,
            event_metadata=_normalized_metadata(item),
            occurred_at=default_occurred_at(item.occurred_at),
        )
        db.add(event)
        db.flush()

        job = enqueue_detection_job(
            db,
            organization_id=current_user.organization_id,
            event_id=event.id,
        )
        job_ids.append(job.id)

        if not payload.defer_detection:
            generated_detections, generated_alerts = process_detection_job(db, job)
            detections_generated += generated_detections
            alerts_generated += generated_alerts

    db.commit()
    return BatchEventIngestResponse(
        events_ingested=len(payload.events),
        detections_generated=detections_generated,
        alerts_generated=alerts_generated,
        job_ids=job_ids,
    )


@router.post("/stream", response_model=BatchEventIngestResponse)
def create_events_stream(
    payload: StreamEventIngestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    detections_generated = 0
    alerts_generated = 0
    job_ids: list[int] = []

    for item in payload.events:
        event = Event(
            organization_id=current_user.organization_id,
            source=item.source,
            source_ip=item.source_ip,
            username=item.username,
            event_type=item.event_type,
            severity=item.severity,
            status=item.status,
            message=item.message,
            event_metadata=_normalized_metadata(item),
            occurred_at=default_occurred_at(item.occurred_at),
        )
        db.add(event)
        db.flush()
        job = enqueue_detection_job(
            db,
            organization_id=current_user.organization_id,
            event_id=event.id,
        )
        job_ids.append(job.id)

        if not payload.defer_detection:
            generated_detections, generated_alerts = process_detection_job(db, job)
            detections_generated += generated_detections
            alerts_generated += generated_alerts

        if payload.inter_event_delay_ms:
            sleep(payload.inter_event_delay_ms / 1000)

    db.commit()
    return BatchEventIngestResponse(
        events_ingested=len(payload.events),
        detections_generated=detections_generated,
        alerts_generated=alerts_generated,
        job_ids=job_ids,
    )


@router.post("/replay", response_model=ReplayEventsResponse)
def replay_events(
    payload: ReplayEventsRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.detection_engineer)),
):
    if payload.from_timestamp > payload.to_timestamp:
        raise HTTPException(status_code=400, detail="from_timestamp must be before to_timestamp")

    source_events = (
        db.query(Event)
        .filter(
            Event.organization_id == current_user.organization_id,
            Event.occurred_at >= payload.from_timestamp,
            Event.occurred_at <= payload.to_timestamp,
        )
        .order_by(Event.occurred_at.asc())
        .all()
    )

    detections_generated = 0
    alerts_generated = 0
    job_ids: list[int] = []
    replayed_events = 0
    for src in source_events:
        seconds_offset = max(0, (src.occurred_at - payload.from_timestamp).total_seconds())
        replay_seconds = seconds_offset / payload.speed_multiplier
        clone = Event(
            organization_id=current_user.organization_id,
            source=src.source,
            source_ip=src.source_ip,
            username=src.username,
            event_type=src.event_type,
            severity=src.severity,
            status=src.status,
            message=f"[replay x{payload.speed_multiplier}] {src.message}",
            event_metadata=dict(src.event_metadata or {}),
            occurred_at=(payload.from_timestamp + timedelta(seconds=replay_seconds)),
        )
        db.add(clone)
        db.flush()
        replayed_events += 1

        job = enqueue_detection_job(db, organization_id=current_user.organization_id, event_id=clone.id)
        job_ids.append(job.id)
        if not payload.defer_detection:
            generated_detections, generated_alerts = process_detection_job(db, job)
            detections_generated += generated_detections
            alerts_generated += generated_alerts

    db.commit()
    return ReplayEventsResponse(
        replayed_events=replayed_events,
        detections_generated=detections_generated,
        alerts_generated=alerts_generated,
        job_ids=job_ids,
    )


@router.get("", response_model=EventListResponse)
def list_events(
    page: int = 1,
    page_size: int = 50,
    event_type: str | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    severity: str | None = None,
    sort_by: str = "occurred_at",
    sort_order: str = "desc",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Event).filter(Event.organization_id == current_user.organization_id)
    if event_type:
        query = query.filter(Event.event_type == event_type)
    if username:
        query = query.filter(Event.username == username)
    if source_ip:
        query = query.filter(Event.source_ip == source_ip)
    if severity:
        query = query.filter(Event.severity == severity)

    sort_column = Event.created_at if sort_by == "created_at" else Event.occurred_at
    query = query.order_by(sort_column.asc() if sort_order == "asc" else sort_column.desc())
    items, total, safe_page, safe_page_size = paginate_query(query, page=page, page_size=page_size)
    return EventListResponse(
        items=items,
        pagination=PaginationMeta(page=safe_page, page_size=safe_page_size, total=total),
    )


@router.get("/scenarios", response_model=list[SeedScenarioOut])
def list_event_scenarios(
    _: User = Depends(get_current_user),
):
    return [
        SeedScenarioOut(
            key=item.key,
            title=item.title,
            description=item.description,
            log_types=list(item.log_types),
            expected_detections=list(item.expected_detections),
        )
        for item in list_seed_scenarios()
    ]


@router.post("/scenarios/{scenario_key}/seed", response_model=SeedScenarioIngestResult)
def seed_event_scenario(
    scenario_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.detection_engineer)),
):
    if scenario_key not in SCENARIO_DEFINITIONS:
        raise HTTPException(status_code=404, detail="Scenario not found")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    events = build_scenario_events(
        scenario_key=scenario_key,
        organization_id=current_user.organization_id,
        now=now,
    )
    db.add_all(events)
    db.flush()

    detections_generated = 0
    alerts_generated = 0
    for event in events:
        job = enqueue_detection_job(
            db,
            organization_id=current_user.organization_id,
            event_id=event.id,
        )
        generated_detections, generated_alerts = process_detection_job(db, job)
        detections_generated += generated_detections
        alerts_generated += generated_alerts

    db.commit()

    return SeedScenarioIngestResult(
        scenario=scenario_key,
        events_ingested=len(events),
        detections_generated=detections_generated,
        alerts_generated=alerts_generated,
    )


@router.post("/simulations/run", response_model=RunSimulationResponse)
def run_demo_simulation(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.detection_engineer)),
):
    scenario_keys = ["brute_force_login_attack", "suspicious_ip_access", "api_abuse_spike"]
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    events_ingested = 0
    detections_generated = 0
    alerts_generated = 0

    for scenario_key in scenario_keys:
        events = build_scenario_events(
            scenario_key=scenario_key,
            organization_id=current_user.organization_id,
            now=now,
        )
        db.add_all(events)
        db.flush()
        events_ingested += len(events)
        for event in events:
            job = enqueue_detection_job(
                db,
                organization_id=current_user.organization_id,
                event_id=event.id,
            )
            generated_detections, generated_alerts = process_detection_job(db, job)
            detections_generated += generated_detections
            alerts_generated += generated_alerts
    db.commit()
    return RunSimulationResponse(
        simulation="soc_attack_chain",
        scenarios_executed=scenario_keys,
        events_ingested=events_ingested,
        detections_generated=detections_generated,
        alerts_generated=alerts_generated,
    )


@router.get("/{event_id}", response_model=EventOut)
def get_event(
    event_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    event = (
        db.query(Event)
        .filter(Event.id == event_id, Event.organization_id == current_user.organization_id)
        .first()
    )
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event
