from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models import AlertStatus, DetectionJobStatus, IncidentStatus, Role


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    full_name: str
    role: Role
    organization_id: int

    model_config = ConfigDict(from_attributes=True)


class EventCreate(BaseModel):
    source: str
    source_ip: str | None = None
    username: str | None = None
    event_type: str
    severity: str = "low"
    status: str = "new"
    message: str
    metadata: dict = Field(default_factory=dict)
    occurred_at: datetime | None = None


class EventOut(BaseModel):
    id: int
    organization_id: int
    source: str
    source_ip: str | None
    username: str | None
    event_type: str
    severity: str
    status: str
    message: str
    metadata: dict = Field(
        validation_alias="event_metadata",
        serialization_alias="metadata",
    )
    occurred_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DetectionOut(BaseModel):
    id: int
    event_id: int
    organization_id: int
    detection_type: str
    detection_method: str
    title: str
    severity: str
    confidence_score: float
    explanation: str
    evidence: list[dict]
    mitre_techniques: list[str]
    recommended_next_steps: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertOut(BaseModel):
    id: int
    organization_id: int
    event_id: int
    detection_id: int
    title: str
    severity: str
    status: AlertStatus
    confidence_score: float
    explanation: str
    evidence: list[dict]
    mitre_techniques: list[str]
    correlation_id: str
    incident_id: int | None
    assigned_analyst_id: int | None
    recommended_next_steps: str
    dedup_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    closed_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class InvestigationNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=4000)


class InvestigationNoteOut(BaseModel):
    id: int
    alert_id: int
    author_id: int
    note: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertAssignRequest(BaseModel):
    analyst_id: int | None = None


class AlertTimelineEntryOut(BaseModel):
    id: int
    alert_id: int
    actor_id: int | None
    action: str
    details: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    summary: str = ""
    alert_ids: list[int] = Field(default_factory=list)
    assigned_analyst_id: int | None = None


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus


class IncidentOut(BaseModel):
    id: int
    organization_id: int
    title: str
    summary: str
    status: IncidentStatus
    created_by_id: int
    assigned_analyst_id: int | None
    created_at: datetime
    closed_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class IncidentAlertLinkRequest(BaseModel):
    alert_ids: list[int] = Field(min_length=1, max_length=500)


class IncidentTimelineEntryOut(BaseModel):
    id: int
    actor_id: int | None
    action: str
    details: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MetricsSummary(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    high_severity_alerts: int
    triaged_alerts: int
    investigating_alerts: int
    escalated_alerts: int
    closed_alerts: int
    mttd_minutes: float
    mttr_minutes: float
    false_positive_rate: float
    detection_coverage: float


class KpiSummary(BaseModel):
    open_alerts: int
    high_severity_alerts: int
    mttd_minutes: float
    mttr_minutes: float
    false_positive_rate: float


class DetectionCatalogEntryOut(BaseModel):
    key: str
    title: str
    severity: str
    default_confidence: float
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    recommendation: str
    description: str
    dedup_window_minutes: int


class SeedScenarioOut(BaseModel):
    key: str
    title: str
    description: str
    log_types: list[str]
    expected_detections: list[str]


class SeedScenarioIngestResult(BaseModel):
    scenario: str
    events_ingested: int
    detections_generated: int
    alerts_generated: int


class RunSimulationResponse(BaseModel):
    simulation: str
    scenarios_executed: list[str]
    events_ingested: int
    detections_generated: int
    alerts_generated: int


class EventIngestResponse(BaseModel):
    event: EventOut
    detections: list[DetectionOut]
    alerts: list[AlertOut]
    job_id: int | None = None


class BatchEventIngestRequest(BaseModel):
    events: list[EventCreate] = Field(min_length=1, max_length=500)
    defer_detection: bool = False


class BatchEventIngestResponse(BaseModel):
    events_ingested: int
    detections_generated: int
    alerts_generated: int
    job_ids: list[int]


class StreamEventIngestRequest(BaseModel):
    events: list[EventCreate] = Field(min_length=1, max_length=500)
    inter_event_delay_ms: int = Field(default=0, ge=0, le=2000)
    defer_detection: bool = False


class ReplayEventsRequest(BaseModel):
    from_timestamp: datetime
    to_timestamp: datetime
    speed_multiplier: float = Field(default=1.0, ge=0.1, le=50.0)
    defer_detection: bool = False


class ReplayEventsResponse(BaseModel):
    replayed_events: int
    detections_generated: int
    alerts_generated: int
    job_ids: list[int]


class PaginationMeta(BaseModel):
    page: int
    page_size: int
    total: int


class EventListResponse(BaseModel):
    items: list[EventOut]
    pagination: PaginationMeta


class AlertListResponse(BaseModel):
    items: list[AlertOut]
    pagination: PaginationMeta


class IncidentListResponse(BaseModel):
    items: list[IncidentOut]
    pagination: PaginationMeta


class DetectionMethodMetrics(BaseModel):
    method: str
    detections: int
    alerts: int
    avg_confidence: float


class DetectionComparisonOut(BaseModel):
    methods: list[DetectionMethodMetrics]


class FeatureFlagOut(BaseModel):
    id: int
    key: str
    enabled: bool
    description: str

    model_config = ConfigDict(from_attributes=True)


class FeatureFlagUpdate(BaseModel):
    enabled: bool


class AuditLogOut(BaseModel):
    id: int
    organization_id: int
    actor_id: int | None
    action: str
    target_type: str
    target_id: int | None
    details: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AnalystFeedbackCreate(BaseModel):
    is_true_positive: bool
    tuning_notes: str = ""


class AnalystFeedbackOut(BaseModel):
    id: int
    organization_id: int
    alert_id: int
    analyst_id: int
    is_true_positive: bool
    tuning_notes: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AiSummaryOut(BaseModel):
    summary: str


class AiTriageOut(BaseModel):
    recommendation: str
    priority: str


class DetectionJobOut(BaseModel):
    id: int
    organization_id: int
    event_id: int
    status: DetectionJobStatus
    detections_generated: int
    alerts_generated: int
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class JobMetricsOut(BaseModel):
    queued: int
    processing: int
    completed: int
    failed: int
    avg_duration_seconds: float


class DetectionQualityOut(BaseModel):
    reviewed_alerts: int
    true_positive_count: int
    false_positive_count: int
    precision: float
    false_positive_rate: float


class ScenarioBenchmarkOut(BaseModel):
    scenario: str
    expected_detections: list[str]
    observed_detections: list[str]
    coverage_percent: float


class CorrelationHotspotOut(BaseModel):
    correlation_id: str
    alert_count: int
    max_dedup_count: int
    avg_confidence: float
