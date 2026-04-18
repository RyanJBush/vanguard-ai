from datetime import datetime

from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class AlertStatusUpdate(BaseModel):
    status: str
