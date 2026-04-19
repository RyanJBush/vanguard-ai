from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models import AlertStatus, Role


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
    confidence_score: float
    explanation: str
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
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class MetricsSummary(BaseModel):
    total_events: int
    total_alerts: int
    open_alerts: int
    high_severity_alerts: int
    detection_coverage: float


class EventIngestResponse(BaseModel):
    event: EventOut
    detections: list[DetectionOut]
    alerts: list[AlertOut]
