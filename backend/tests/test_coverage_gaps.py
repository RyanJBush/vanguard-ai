import os
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

os.environ["VANGUARD_DATABASE_URL"] = "sqlite:///./test_coverage_gaps.db"

from app.db import Base, get_db
from app.dependencies import get_current_user
from app.main import app
from app.models import Organization, Role, User
from app.security import decode_access_token, hash_password
from app.services.ai_assistant import build_triage_recommendation

TEST_DATABASE_URL = "sqlite:///./test_coverage_gaps.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    org = Organization(name="Coverage Test Org")
    db.add(org)
    db.flush()
    db.add(
        User(
            username="admin",
            full_name="Admin User",
            password_hash=hash_password("admin123"),
            role=Role.admin,
            organization_id=org.id,
        )
    )
    db.commit()
    db.close()


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client():
    def override_get_db():
        db: Session = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _auth_headers(client: TestClient) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_ai_triage_priority_branches_for_medium_and_low_severity():
    medium_alert = SimpleNamespace(
        severity="medium",
        correlation_id="corr-medium",
        recommended_next_steps="isolate host",
    )
    low_alert = SimpleNamespace(
        severity="low",
        correlation_id="corr-low",
        recommended_next_steps=None,
    )

    medium_reco, medium_priority = build_triage_recommendation(medium_alert)
    low_reco, low_priority = build_triage_recommendation(low_alert)

    assert medium_priority == "P2"
    assert "Prioritize P2 triage" in medium_reco
    assert low_priority == "P3"
    assert "collect supporting evidence." in low_reco


def test_decode_access_token_rejects_invalid_token():
    with pytest.raises(HTTPException, match="Invalid token"):
        decode_access_token("not-a-real-jwt")


def test_get_current_user_rejects_missing_subject(monkeypatch, db_session):
    monkeypatch.setattr("app.dependencies.decode_access_token", lambda _token: {})

    with pytest.raises(HTTPException, match="Invalid token"):
        get_current_user(token="ignored", db=db_session)


def test_get_current_user_rejects_unknown_user(monkeypatch, db_session):
    monkeypatch.setattr(
        "app.dependencies.decode_access_token",
        lambda _token: {"sub": "missing-user"},
    )

    with pytest.raises(HTTPException, match="User not found"):
        get_current_user(token="ignored", db=db_session)


def test_auth_invalid_login_and_me_endpoint(client: TestClient):
    failed = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "wrong-password"},
    )
    assert failed.status_code == 401

    headers = _auth_headers(client)
    me = client.get("/api/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["username"] == "admin"


def test_health_dependencies_reports_degraded_when_db_fails():
    class BrokenDB:
        def execute(self, *_args, **_kwargs):
            raise RuntimeError("db unavailable")

    def broken_db_override():
        yield BrokenDB()

    app.dependency_overrides[get_db] = broken_db_override
    try:
        with TestClient(app) as test_client:
            response = test_client.get("/health/dependencies")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["dependencies"]["database"] == "unreachable"


def test_events_filter_and_missing_resources(client: TestClient):
    headers = _auth_headers(client)

    first = {
        "source": "identity_provider",
        "source_ip": "198.51.100.7",
        "username": "jdoe",
        "event_type": "login_failed",
        "severity": "high",
        "message": "Failed login",
        "occurred_at": datetime(2026, 4, 18, 12, 0, tzinfo=UTC).isoformat(),
    }
    second = {
        "source": "identity_provider",
        "source_ip": "198.51.100.8",
        "username": "jdoe",
        "event_type": "access_denied",
        "severity": "low",
        "message": "Access denied",
        "occurred_at": datetime(2026, 4, 18, 12, 5, tzinfo=UTC).isoformat(),
    }

    assert (
        client.post("/api/events?defer_detection=true", json=first, headers=headers).status_code
        == 200
    )
    assert (
        client.post("/api/events?defer_detection=true", json=second, headers=headers).status_code
        == 200
    )

    filtered = client.get(
        "/api/events?event_type=login_failed&severity=high",
        headers=headers,
    )
    assert filtered.status_code == 200
    items = filtered.json()["items"]
    assert len(items) == 1
    assert items[0]["event_type"] == "login_failed"
    assert items[0]["severity"] == "high"

    not_found = client.get("/api/events/999999", headers=headers)
    assert not_found.status_code == 404

    bad_scenario = client.post("/api/events/scenarios/not-real/seed", headers=headers)
    assert bad_scenario.status_code == 404


def test_incident_missing_and_invalid_alert_paths(client: TestClient):
    headers = _auth_headers(client)

    missing_get = client.get("/api/incidents/999999", headers=headers)
    assert missing_get.status_code == 404

    missing_patch = client.patch(
        "/api/incidents/999999/status",
        json={"status": "closed"},
        headers=headers,
    )
    assert missing_patch.status_code == 404

    missing_wrapup = client.get("/api/incidents/999999/ai-wrapup", headers=headers)
    assert missing_wrapup.status_code == 404

    invalid_alert = client.post(
        "/api/incidents",
        json={"title": "Bad Incident", "summary": "No valid alerts", "alert_ids": [12345]},
        headers=headers,
    )
    assert invalid_alert.status_code == 400


def test_incident_reopen_clears_closed_timestamp(client: TestClient):
    headers = _auth_headers(client)

    created = client.post(
        "/api/incidents",
        json={"title": "Incident", "summary": "Needs follow-up", "alert_ids": []},
        headers=headers,
    )
    assert created.status_code == 200
    incident_id = created.json()["id"]

    closed = client.patch(
        f"/api/incidents/{incident_id}/status",
        json={"status": "closed"},
        headers=headers,
    )
    assert closed.status_code == 200
    assert closed.json()["closed_at"] is not None

    reopened = client.patch(
        f"/api/incidents/{incident_id}/status",
        json={"status": "investigating"},
        headers=headers,
    )
    assert reopened.status_code == 200
    assert reopened.json()["closed_at"] is None


def test_platform_and_alert_404_paths(client: TestClient):
    headers = _auth_headers(client)

    missing_flag = client.patch(
        "/api/platform/feature-flags/not_a_real_flag",
        json={"enabled": False},
        headers=headers,
    )
    assert missing_flag.status_code == 404

    missing_alert = client.get("/api/alerts/999999", headers=headers)
    assert missing_alert.status_code == 404
