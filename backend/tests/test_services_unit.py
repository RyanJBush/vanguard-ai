from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import (
    DetectionJob,
    DetectionJobStatus,
    Event,
    FeatureFlag,
    Organization,
    Role,
    User,
)
from app.security import hash_password
from app.services import job_service
from app.services.seed import seed_demo_data
from app.services.seed_scenarios import build_scenario_events, list_seed_scenarios

TEST_DATABASE_URL = "sqlite:///./test_services.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


def _create_org_and_user(db_session):
    org = Organization(name="Unit Test Org")
    db_session.add(org)
    db_session.flush()
    user = User(
        username="admin",
        full_name="Admin User",
        password_hash=hash_password("admin123"),
        role=Role.admin,
        organization_id=org.id,
    )
    db_session.add(user)
    db_session.commit()
    return org, user


def _create_event(db_session, *, organization_id: int):
    event = Event(
        organization_id=organization_id,
        source="identity_provider",
        source_ip="203.0.113.7",
        username="jdoe",
        event_type="login_failed",
        severity="medium",
        message="Failed login",
        occurred_at=datetime.now(timezone.utc).replace(tzinfo=None),
        event_metadata={"known_benign": False},
    )
    db_session.add(event)
    db_session.flush()
    return event


def test_process_detection_job_marks_missing_event_as_failed(db_session):
    org, _ = _create_org_and_user(db_session)
    job = job_service.enqueue_detection_job(db_session, organization_id=org.id, event_id=999_999)

    detections_count, alerts_count = job_service.process_detection_job(db_session, job)

    assert detections_count == 0
    assert alerts_count == 0
    assert job.status == DetectionJobStatus.failed
    assert job.error_message == "Event not found"
    assert job.completed_at is not None


def test_process_detection_job_marks_exception_as_failed(db_session, monkeypatch):
    org, _ = _create_org_and_user(db_session)
    event = _create_event(db_session, organization_id=org.id)
    job = job_service.enqueue_detection_job(db_session, organization_id=org.id, event_id=event.id)

    def _boom(*_args, **_kwargs):
        raise RuntimeError("detection exploded")

    monkeypatch.setattr(job_service, "detect_event", _boom)

    with pytest.raises(RuntimeError, match="detection exploded"):
        job_service.process_detection_job(db_session, job)

    assert job.status == DetectionJobStatus.failed
    assert job.started_at is not None
    assert job.completed_at is not None
    assert job.error_message == "detection exploded"


def test_process_pending_jobs_enforces_minimum_limit(db_session, monkeypatch):
    org, _ = _create_org_and_user(db_session)
    event_one = _create_event(db_session, organization_id=org.id)
    event_two = _create_event(db_session, organization_id=org.id)
    job_one = job_service.enqueue_detection_job(db_session, organization_id=org.id, event_id=event_one.id)
    job_two = job_service.enqueue_detection_job(db_session, organization_id=org.id, event_id=event_two.id)
    db_session.flush()

    processed_ids: list[int] = []

    def _fake_process(_db, job):
        processed_ids.append(job.id)
        job.status = DetectionJobStatus.completed
        return 0, 0

    monkeypatch.setattr(job_service, "process_detection_job", _fake_process)

    jobs = job_service.process_pending_jobs(db_session, organization_id=org.id, limit=0)

    assert len(jobs) == 1
    assert processed_ids == [job_one.id]
    assert job_two.status == DetectionJobStatus.queued


def test_seed_demo_data_returns_early_when_users_exist(db_session):
    _create_org_and_user(db_session)

    seed_demo_data(db_session)

    assert db_session.query(User).count() == 1
    assert db_session.query(Event).count() == 0


def test_seed_demo_data_creates_data_and_processes_jobs(db_session, monkeypatch):
    enqueued_event_ids: list[int] = []
    processed_event_ids: list[int] = []

    def _fake_enqueue(_db, *, organization_id: int, event_id: int):
        enqueued_event_ids.append(event_id)
        return SimpleNamespace(id=event_id, organization_id=organization_id, event_id=event_id)

    def _fake_process(_db, job):
        processed_event_ids.append(job.event_id)
        return 0, 0

    monkeypatch.setattr("app.services.seed.enqueue_detection_job", _fake_enqueue)
    monkeypatch.setattr("app.services.seed.process_detection_job", _fake_process)

    seed_demo_data(db_session)

    assert db_session.query(Organization).count() == 1
    assert db_session.query(User).count() == 4
    assert db_session.query(Event).count() == 12
    assert db_session.query(FeatureFlag).count() >= 4
    assert len(enqueued_event_ids) == 12
    assert len(processed_event_ids) == 12
    assert set(processed_event_ids) == set(enqueued_event_ids)


def test_list_seed_scenarios_and_build_command_and_control_events():
    scenario_keys = {scenario.key for scenario in list_seed_scenarios()}
    assert "credential_access_password_spray" in scenario_keys
    assert "identity_privilege_escalation" in scenario_keys
    assert "command_and_control_egress" in scenario_keys

    now = datetime(2026, 4, 20, 12, 0, tzinfo=timezone.utc)
    events = build_scenario_events(
        scenario_key="command_and_control_egress",
        organization_id=1,
        now=now,
    )
    assert len(events) == 2
    assert {event.source for event in events} == {"endpoint", "firewall"}


def test_build_scenario_events_rejects_unknown_scenario():
    with pytest.raises(ValueError, match="Unsupported scenario: unknown"):
        build_scenario_events(
            scenario_key="unknown",
            organization_id=1,
            now=datetime(2026, 4, 20, 12, 0, tzinfo=timezone.utc),
        )


def test_build_scenario_events_supports_phase6_scenarios():
    now = datetime(2026, 4, 20, 12, 0, tzinfo=timezone.utc)
    brute = build_scenario_events(
        scenario_key="brute_force_login_attack",
        organization_id=1,
        now=now,
    )
    suspicious = build_scenario_events(
        scenario_key="suspicious_ip_access",
        organization_id=1,
        now=now,
    )
    api_spike = build_scenario_events(
        scenario_key="api_abuse_spike",
        organization_id=1,
        now=now,
    )
    assert len(brute) >= 5
    assert any(event.event_type == "login_success" for event in suspicious)
    assert len(api_spike) >= 25


def test_get_db_generator_closes_session(monkeypatch):
    from app import db as db_module

    class DummySession:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    session = DummySession()
    monkeypatch.setattr(db_module, "SessionLocal", lambda: session)

    db_gen = db_module.get_db()
    yielded = next(db_gen)
    assert yielded is session
    db_gen.close()
    assert session.closed is True
