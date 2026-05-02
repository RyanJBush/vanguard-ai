from __future__ import annotations

import logging
import os
import asyncio
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker

os.environ["VANGUARD_DATABASE_URL"] = "sqlite:///./test_additional_coverage.db"

from app.db import Base
from app.dependencies import require_roles
from app.models import Organization
from app.models import DetectionJobStatus, Role
from app.observability import RequestContextFilter, request_id_ctx, request_tracing_middleware
from app.services import job_service

engine = create_engine("sqlite:///./test_additional_coverage.db", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    db.add(Organization(name="Additional Coverage Org"))
    db.commit()
    db.close()


@pytest.fixture
def db_session() -> Session:
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


class DummyRequest:
    def __init__(self, *, method: str = "GET", path: str = "/ping", headers: dict | None = None):
        self.method = method
        self.url = type("URL", (), {"path": path})()
        self.headers = headers or {}


class DummyResponse:
    def __init__(self):
        self.headers: dict[str, str] = {}


def test_request_tracing_middleware_uses_existing_request_id_and_resets_context():
    request = DummyRequest(headers={"x-request-id": "trace-123"})

    async def next_handler(_request):
        assert request_id_ctx.get() == "trace-123"
        return DummyResponse()

    response = asyncio.run(request_tracing_middleware(request, next_handler))
    assert response.headers["x-request-id"] == "trace-123"
    assert request_id_ctx.get() == "-"


def test_request_tracing_middleware_generates_request_id_when_missing():
    request = DummyRequest(headers={})

    async def next_handler(_request):
        return DummyResponse()

    response = asyncio.run(request_tracing_middleware(request, next_handler))
    assert "x-request-id" in response.headers
    assert len(response.headers["x-request-id"]) >= 8


def test_request_context_filter_adds_request_id_to_record():
    request_id_ctx.set("rid-42")
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello",
        args=(),
        exc_info=None,
    )
    assert RequestContextFilter().filter(record) is True
    assert record.request_id == "rid-42"


def test_require_roles_allows_authorized_and_rejects_unauthorized():
    guard = require_roles(Role.admin)
    allowed_user = type("U", (), {"role": Role.admin})()
    denied_user = type("U", (), {"role": Role.viewer})()

    assert guard(allowed_user) is allowed_user
    with pytest.raises(Exception) as exc_info:
        guard(denied_user)
    assert getattr(exc_info.value, "status_code", None) == 403


def test_process_detection_job_marks_missing_event_failed(db_session: Session):
    job = job_service.enqueue_detection_job(db_session, organization_id=1, event_id=999999)
    generated = job_service.process_detection_job(db_session, job)

    assert generated == (0, 0)
    assert job.status == DetectionJobStatus.failed
    assert job.error_message == "Event not found"
    assert isinstance(job.completed_at, datetime)


def test_process_pending_jobs_clamps_limit_and_processes_only_queued(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
):
    queued_jobs = [job_service.enqueue_detection_job(db_session, organization_id=1, event_id=i) for i in [11, 12, 13]]
    completed_job = job_service.enqueue_detection_job(db_session, organization_id=1, event_id=99)
    completed_job.status = DetectionJobStatus.completed
    db_session.flush()

    seen: list[int] = []

    def fake_process(_db, job):
        seen.append(job.id)
        job.status = DetectionJobStatus.completed
        return (1, 1)

    monkeypatch.setattr(job_service, "process_detection_job", fake_process)

    returned = job_service.process_pending_jobs(db_session, organization_id=1, limit=0)

    assert len(returned) == 1
    assert seen == [queued_jobs[0].id]
    assert completed_job.id not in seen
