import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

os.environ['VANGUARD_DATABASE_URL'] = 'sqlite:///./test_rbac.db'

import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from app.db import Base, get_db
from app.main import app
from app.models import Organization, Role, User
from app.security import hash_password

TEST_DATABASE_URL = 'sqlite:///./test_rbac.db'
engine = create_engine(TEST_DATABASE_URL, connect_args={'check_same_thread': False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    org = Organization(name='RBAC Org')
    db.add(org)
    db.flush()
    users = [
        User(
            username='admin',
            full_name='Admin User',
            password_hash=hash_password('admin123'),
            role=Role.admin,
            organization_id=org.id,
        ),
        User(
            username='viewer',
            full_name='Viewer User',
            password_hash=hash_password('viewer123'),
            role=Role.viewer,
            organization_id=org.id,
        ),
    ]
    db.add_all(users)
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


def _auth_headers(client: TestClient, username: str, password: str) -> dict[str, str]:
    response = client.post('/api/auth/login', json={'username': username, 'password': password})
    assert response.status_code == 200
    token = response.json()['access_token']
    return {'Authorization': f'Bearer {token}'}


def test_viewer_cannot_seed_scenarios(client: TestClient):
    headers = _auth_headers(client, 'viewer', 'viewer123')
    response = client.post('/api/events/scenarios/credential_access_password_spray/seed', headers=headers)
    assert response.status_code == 403


def test_viewer_cannot_process_jobs(client: TestClient):
    headers = _auth_headers(client, 'viewer', 'viewer123')
    response = client.post('/api/jobs/process-pending', headers=headers)
    assert response.status_code == 403


def test_admin_can_process_jobs(client: TestClient):
    headers = _auth_headers(client, 'admin', 'admin123')
    response = client.post('/api/jobs/process-pending', headers=headers)
    assert response.status_code == 200
