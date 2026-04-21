from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.dependencies import get_current_user, require_roles
from app.models import AuditLog, FeatureFlag, Role, User
from app.schemas import AuditLogOut, FeatureFlagOut, FeatureFlagUpdate
from app.services.audit import write_audit_log
from app.services.feature_flags import ensure_default_feature_flags

router = APIRouter(prefix="/api/platform", tags=["platform"])


@router.get("/feature-flags", response_model=list[FeatureFlagOut])
def list_feature_flags(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.detection_engineer)),
):
    ensure_default_feature_flags(db, current_user.organization_id)
    db.commit()
    return (
        db.query(FeatureFlag)
        .filter(FeatureFlag.organization_id == current_user.organization_id)
        .order_by(FeatureFlag.key.asc())
        .all()
    )


@router.patch("/feature-flags/{flag_key}", response_model=FeatureFlagOut)
def patch_feature_flag(
    flag_key: str,
    payload: FeatureFlagUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.detection_engineer)),
):
    ensure_default_feature_flags(db, current_user.organization_id)
    flag = (
        db.query(FeatureFlag)
        .filter(FeatureFlag.organization_id == current_user.organization_id, FeatureFlag.key == flag_key)
        .first()
    )
    if not flag:
        raise HTTPException(status_code=404, detail="Feature flag not found")

    flag.enabled = payload.enabled
    write_audit_log(
        db,
        organization_id=current_user.organization_id,
        actor_id=current_user.id,
        action="feature_flag_updated",
        target_type="feature_flag",
        target_id=flag.id,
        details=f"{flag.key} set to {payload.enabled}",
    )
    db.commit()
    db.refresh(flag)
    return flag


@router.get("/audit-logs", response_model=list[AuditLogOut])
def list_audit_logs(
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(Role.admin, Role.detection_engineer)),
):
    return (
        db.query(AuditLog)
        .filter(AuditLog.organization_id == current_user.organization_id)
        .order_by(AuditLog.created_at.desc())
        .limit(min(max(limit, 1), 500))
        .all()
    )
