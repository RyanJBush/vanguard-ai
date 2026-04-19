from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models import Event, Organization, Role, User
from app.security import hash_password


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
            username="viewer",
            full_name="Viv Viewer",
            password_hash=hash_password("viewer123"),
            role=Role.viewer,
            organization_id=org.id,
        ),
    ]
    db.add_all(users)

    now = datetime.now(UTC).replace(tzinfo=None)
    events = [
        Event(
            organization_id=org.id,
            source="identity_provider",
            source_ip="10.8.2.44",
            username="jdoe",
            event_type="login_failed",
            severity="medium",
            message="Failed login attempt due to invalid password",
            occurred_at=now - timedelta(minutes=8),
            event_metadata={"country": "US", "device": "Windows"},
        ),
        Event(
            organization_id=org.id,
            source="vpn_gateway",
            source_ip="192.168.22.5",
            username="jdoe",
            event_type="login_success",
            severity="low",
            message="User login succeeded",
            occurred_at=now - timedelta(hours=1),
            event_metadata={"country": "DE", "device": "Linux"},
        ),
        Event(
            organization_id=org.id,
            source="iam",
            source_ip="10.10.4.1",
            username="svc-backup",
            event_type="privilege_change",
            severity="high",
            message="Admin role granted to service account",
            occurred_at=now - timedelta(minutes=20),
            event_metadata={"ticket": "INC-1088"},
        ),
    ]
    db.add_all(events)
    db.commit()
