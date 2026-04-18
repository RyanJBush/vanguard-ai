from datetime import datetime

from pydantic import BaseModel


class DetectionResponse(BaseModel):
    id: int
    event_id: int
    rule_name: str
    confidence: float
    created_at: datetime

    class Config:
        from_attributes = True
