from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import Event, Organization
from app.services.detection_service import detect_event

engine = create_engine("sqlite:///./test_detection_phase1.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def setup_function():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def _create_org(db):
    org = Organization(name="Detection Test Org")
    db.add(org)
    db.flush()
    return org


def _add_event(db, org_id: int, **kwargs):
    event = Event(
        organization_id=org_id,
        source=kwargs.get("source", "gateway"),
        source_ip=kwargs.get("source_ip", "198.51.100.10"),
        username=kwargs.get("username", "user1"),
        event_type=kwargs.get("event_type", "login_failed"),
        severity=kwargs.get("severity", "medium"),
        status=kwargs.get("status", "new"),
        message=kwargs.get("message", "test"),
        occurred_at=kwargs.get("occurred_at"),
        event_metadata=kwargs.get("event_metadata", {}),
    )
    db.add(event)
    db.flush()
    return event


def test_brute_force_and_evidence_generated():
    db = SessionLocal()
    try:
        org = _create_org(db)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        for idx in range(5):
            current = _add_event(
                db,
                org.id,
                event_type="login_failed",
                source_ip="203.0.113.99",
                username=f"user{idx}",
                occurred_at=now - timedelta(minutes=idx),
            )
        signals = detect_event(db, current)
        brute_force = next(item for item in signals if item.name == "brute_force_login_rule")
        assert brute_force.severity == "high"
        assert brute_force.confidence >= 0.7
        assert brute_force.evidence
    finally:
        db.close()


def test_abnormal_request_spike_and_suspicious_ip_behavior():
    db = SessionLocal()
    try:
        org = _create_org(db)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        for idx in range(26):
            _add_event(
                db,
                org.id,
                event_type="api_request",
                source_ip="198.51.100.77",
                username=f"svc{idx % 2}",
                occurred_at=now - timedelta(minutes=1),
            )

        for idx in range(6):
            _add_event(
                db,
                org.id,
                event_type="login_failed",
                source_ip="198.51.100.77",
                username=f"employee{idx % 3}",
                occurred_at=now - timedelta(minutes=2),
            )

        trigger = _add_event(
            db,
            org.id,
            event_type="login_success",
            source_ip="198.51.100.77",
            username="employee1",
            occurred_at=now,
        )

        signals = detect_event(db, trigger)
        names = {item.name for item in signals}
        assert "suspicious_ip_behavior_rule" in names

        api_trigger = _add_event(
            db,
            org.id,
            event_type="api_request",
            source_ip="198.51.100.77",
            username="svc0",
            occurred_at=now,
        )
        api_signals = detect_event(db, api_trigger)
        assert any(item.name == "abnormal_request_spike_rule" for item in api_signals)
    finally:
        db.close()
