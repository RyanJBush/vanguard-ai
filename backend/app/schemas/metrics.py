from pydantic import BaseModel


class SummaryMetrics(BaseModel):
    events_24h: int
    detections_24h: int
    alerts_open: int
    alerts_investigating: int
    alerts_resolved: int
