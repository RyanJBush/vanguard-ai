import os
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

os.environ["VANGUARD_DATABASE_URL"] = "sqlite:///./test.db"

from app.db import Base, get_db
from app.main import app
from app.models import Organization, Role, User
from app.security import hash_password

TEST_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    org = Organization(name="Test Org")
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


def auth_headers(client: TestClient) -> dict[str, str]:
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_brute_force_alert_generation(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "10.0.0.5",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(4):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200

    fifth = client.post("/api/events", json=payload, headers=headers)
    assert fifth.status_code == 200
    assert any(
        item["detection_type"] == "brute_force_login_rule"
        for item in fifth.json()["detections"]
    )

    alerts = client.get("/api/alerts", headers=headers)
    assert alerts.status_code == 200
    assert len(alerts.json()) >= 1


def test_unusual_hour_detection(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "vpn_gateway",
        "source_ip": "192.168.1.20",
        "username": "analyst",
        "event_type": "login_success",
        "message": "After-hours login",
        "occurred_at": datetime(2026, 4, 18, 2, 0, tzinfo=UTC).isoformat(),
    }
    response = client.post("/api/events", json=payload, headers=headers)
    assert response.status_code == 200
    detection_types = {d["detection_type"] for d in response.json()["detections"]}
    assert "unusual_login_hour_anomaly" in detection_types
