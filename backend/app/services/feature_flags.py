from sqlalchemy.orm import Session

from app.models import FeatureFlag

DEFAULT_FEATURE_FLAGS: dict[str, str] = {
    "brute_force_login_rule": "Enable brute-force login correlation detection.",
    "unusual_login_hour_anomaly": "Enable unusual login hour anomaly detection.",
    "privilege_escalation_indicator": "Enable privilege escalation indicator detection.",
    "high_volume_failed_access_anomaly": "Enable high-volume failed access anomaly detection.",
}


def ensure_default_feature_flags(db: Session, organization_id: int) -> None:
    existing_keys = {
        key
        for (key,) in (
            db.query(FeatureFlag.key)
            .filter(FeatureFlag.organization_id == organization_id)
            .all()
        )
    }
    to_create = [
        FeatureFlag(
            organization_id=organization_id,
            key=key,
            enabled=True,
            description=description,
        )
        for key, description in DEFAULT_FEATURE_FLAGS.items()
        if key not in existing_keys
    ]
    if to_create:
        db.add_all(to_create)
        db.flush()


def is_detection_enabled(db: Session, *, organization_id: int, detection_key: str) -> bool:
    flag = (
        db.query(FeatureFlag)
        .filter(FeatureFlag.organization_id == organization_id, FeatureFlag.key == detection_key)
        .first()
    )
    return True if flag is None else bool(flag.enabled)
