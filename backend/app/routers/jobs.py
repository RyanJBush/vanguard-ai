from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user, require_roles
from app.models import DetectionJob, Role, User
from app.schemas import DetectionJobOut
from app.services.job_service import process_pending_jobs

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


@router.get("", response_model=list[DetectionJobOut])
def list_jobs(
    status: str | None = None,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.detection_engineer)),
):
    query = db.query(DetectionJob).filter(DetectionJob.organization_id == current_user.organization_id)
    if status:
        query = query.filter(DetectionJob.status == status)
    return query.order_by(DetectionJob.created_at.desc()).limit(min(max(limit, 1), 500)).all()


@router.post("/process-pending", response_model=list[DetectionJobOut])
def process_jobs(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.detection_engineer)),
):
    jobs = process_pending_jobs(db, organization_id=current_user.organization_id, limit=limit)
    db.commit()
    return jobs
