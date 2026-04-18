"""Generate demo SOC events for portfolio scenarios."""

from datetime import datetime, timedelta
from random import choice, randint

from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models import Event, Organization, User
from app.services.auth_service import seed_demo_users
from app.services.ingestion_service import ingestion_service
from app.schemas.events import EventIngestRequest

EVENT_TEMPLATES = [
    ("login", "low"),
    ("failed_login", "medium"),
    ("access_denied", "medium"),
    ("role_change", "high"),
    ("process_spawn", "low"),
]


def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_demo_users(db)
        org = db.query(Organization).filter(Organization.name == "Vanguard SOC").first()
        analyst = db.query(User).filter(User.username == "analyst").first()

        for idx in range(50):
            event_type, severity = choice(EVENT_TEMPLATES)
            payload = {
                "failed_count": randint(1, 9),
                "failed_access_count": randint(5, 30),
                "host": f"workstation-{randint(1,25)}",
            }
            event_in = EventIngestRequest(
                event_type=event_type,
                source_ip=f"10.10.{randint(0, 10)}.{randint(1, 254)}",
                actor=analyst.username if analyst else "system",
                severity=severity,
                occurred_at=datetime.utcnow() - timedelta(minutes=idx * 5),
                payload=payload,
            )
            ingestion_service.ingest_event(db, org.id, event_in)

        total_events = db.query(Event).count()
        print(f"Seed complete. Total events in DB: {total_events}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
