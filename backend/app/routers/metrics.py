from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.auth import UserContext
from app.schemas.metrics import SummaryMetrics
from app.services.dependencies import get_current_user_context
from app.services.metrics_service import metrics_service

router = APIRouter(prefix="/metrics")


@router.get("/summary", response_model=SummaryMetrics)
def get_summary_metrics(
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user_context),
) -> SummaryMetrics:
    return metrics_service.get_summary(db, current_user.organization_id)
