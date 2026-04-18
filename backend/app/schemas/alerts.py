from datetime import datetime

from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: int
    event_id: int
    title: str
    description: str
    severity: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class AlertStatusUpdate(BaseModel):
    status: str


class InvestigationNoteCreate(BaseModel):
    note: str


class InvestigationNoteResponse(BaseModel):
    id: int
    alert_id: int
    author_id: int
    note: str
    created_at: datetime

    class Config:
        from_attributes = True
