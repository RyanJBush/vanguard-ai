from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.models import Event, Organization, Role, User
from app.security import hash_password
from app.services.feature_flags import ensure_default_feature_flags
from app.services.job_service import enqueue_detection_job, process_detection_job
from app.services.seed_scenarios import build_scenario_events


def seed_demo_data(db: Session) -> None:
    if db.query(User).count() > 0:
        return

    org = Organization(name="Vanguard Demo Org")
    db.add(org)
    db.flush()

    users = [
        User(
            username="admin",
            full_name="Avery Admin",
            password_hash=hash_password("admin123"),
            role=Role.admin,
            organization_id=org.id,
        ),
        User(
            username="analyst",
            full_name="Sam Analyst",
            password_hash=hash_password("analyst123"),
            role=Role.analyst,
            organization_id=org.id,
        ),
        User(
            username="deteng",
            full_name="Devon Detection Engineer",
            password_hash=hash_password("deteng123"),
            role=Role.detection_engineer,
            organization_id=org.id,
        ),
        User(
            username="viewer",
            full_name="Viv Viewer",
            password_hash=hash_password("viewer123"),
            role=Role.viewer,
            organization_id=org.id,
        ),
    ]
    db.add_all(users)
    ensure_default_feature_flags(db, org.id)

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    baseline_events = [
        Event(
            organization_id=org.id,
            source="auth",
            source_ip="10.8.2.44",
            username="jdoe",
            event_type="login_failed",
            severity="medium",
            message="Failed login attempt due to invalid password",
            occurred_at=now - timedelta(minutes=8),
            event_metadata={
                "log_type": "auth",
                "geolocation": "US",
                "hostname": "wkstn-101",
                "department": "Finance",
                "user_role": "Analyst",
                "asset_criticality": "medium",
                "scenario": "baseline_auth_noise",
                "known_benign": True,
            },
        ),
    ]

    scenario_events = []
    for key in [
        "credential_access_password_spray",
        "identity_privilege_escalation",
        "command_and_control_egress",
    ]:
        scenario_events.extend(build_scenario_events(scenario_key=key, organization_id=org.id, now=now))

    events = baseline_events + scenario_events
    db.add_all(events)
    db.flush()
    for event in events:
        job = enqueue_detection_job(db, organization_id=org.id, event_id=event.id)
        process_detection_job(db, job)
    db.commit()
