from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EventIngestRequest(BaseModel):
    event_type: str
    source_ip: str
    actor: str
    severity: str = "low"
    occurred_at: datetime
    payload: dict[str, Any] = Field(default_factory=dict)


class EventResponse(BaseModel):
    id: int
    event_type: str
    source_ip: str
    actor: str
    severity: str
    occurred_at: datetime

    class Config:
        from_attributes = True
