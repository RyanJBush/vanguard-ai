import os
from datetime import datetime, timezone

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

    ready = client.get("/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"

    deps = client.get("/health/dependencies")
    assert deps.status_code == 200
    assert "database" in deps.json()["dependencies"]


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
    assert len(alerts.json()["items"]) >= 1


def test_unusual_hour_detection(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "vpn_gateway",
        "source_ip": "192.168.1.20",
        "username": "analyst",
        "event_type": "login_success",
        "message": "After-hours login",
        "occurred_at": datetime(2026, 4, 18, 2, 0, tzinfo=timezone.utc).isoformat(),
    }
    response = client.post("/api/events", json=payload, headers=headers)
    assert response.status_code == 200
    detection_types = {d["detection_type"] for d in response.json()["detections"]}
    assert "unusual_login_hour_anomaly" in detection_types


def test_alert_deduplication_and_correlation(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "203.0.113.10",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(6):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200

    alerts = client.get("/api/alerts", headers=headers)
    assert alerts.status_code == 200
    brute_force_alerts = [
        alert
        for alert in alerts.json()["items"]
        if alert["correlation_id"].startswith("brute_force_login_rule")
    ]
    assert len(brute_force_alerts) == 1
    assert brute_force_alerts[0]["dedup_count"] >= 2


def test_investigation_notes_and_expanded_statuses(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "198.51.100.11",
        "username": "analyst",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(5):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200

    alerts = client.get("/api/alerts", headers=headers).json()["items"]
    alert_id = alerts[0]["id"]

    for status in ["triaged", "investigating", "escalated"]:
        updated = client.patch(
            f"/api/alerts/{alert_id}/status",
            json={"status": status},
            headers=headers,
        )
        assert updated.status_code == 200
        assert updated.json()["status"] == status
        assert updated.json()["closed_at"] is None

    closed = client.patch(
        f"/api/alerts/{alert_id}/status",
        json={"status": "closed"},
        headers=headers,
    )
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"
    assert closed.json()["closed_at"] is not None

    note = client.post(
        f"/api/alerts/{alert_id}/notes",
        json={"note": "Escalated to incident response due to persistent source activity."},
        headers=headers,
    )
    assert note.status_code == 200

    notes = client.get(f"/api/alerts/{alert_id}/notes", headers=headers)
    assert notes.status_code == 200
    assert any("Escalated to incident response" in item["note"] for item in notes.json())


def test_metrics_summary_includes_phase1_kpis(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "192.0.2.55",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(5):
        client.post("/api/events", json=payload, headers=headers)

    alerts = client.get("/api/alerts", headers=headers).json()["items"]
    alert_id = alerts[0]["id"]
    client.patch(f"/api/alerts/{alert_id}/status", json={"status": "closed"}, headers=headers)

    summary = client.get("/api/metrics/summary", headers=headers)
    assert summary.status_code == 200
    body = summary.json()
    assert "mttd_minutes" in body
    assert "mttr_minutes" in body
    assert "false_positive_rate" in body
    assert body["closed_alerts"] >= 1


def test_detection_catalog_metadata_exposed(client: TestClient):
    headers = auth_headers(client)
    catalog = client.get("/api/detections/catalog", headers=headers)
    assert catalog.status_code == 200
    brute_force_definition = next(
        item
        for item in catalog.json()
        if item["key"] == "brute_force_login_rule"
    )
    assert "T1110" in brute_force_definition["mitre_techniques"]
    assert "Credential Access" in brute_force_definition["mitre_tactics"]
    assert brute_force_definition["description"]

    payload = {
        "source": "identity_provider",
        "source_ip": "203.0.113.22",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(5):
        client.post("/api/events", json=payload, headers=headers)

    detections = client.get("/api/detections", headers=headers)
    assert detections.status_code == 200
    brute_force = next(
        item
        for item in detections.json()
        if item["detection_type"] == "brute_force_login_rule"
    )
    assert "T1110" in brute_force["mitre_techniques"]
    assert brute_force["recommended_next_steps"]


def test_seed_scenario_endpoint_generates_events_and_alerts(client: TestClient):
    headers = auth_headers(client)
    scenarios = client.get("/api/events/scenarios", headers=headers)
    assert scenarios.status_code == 200
    assert any(item["key"] == "credential_access_password_spray" for item in scenarios.json())

    ingest = client.post(
        "/api/events/scenarios/credential_access_password_spray/seed",
        headers=headers,
    )
    assert ingest.status_code == 200
    assert ingest.json()["events_ingested"] >= 5

    alerts = client.get("/api/alerts", headers=headers)
    assert alerts.status_code == 200
    assert len(alerts.json()["items"]) >= 1


def test_metrics_kpis_endpoint(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "198.51.100.200",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(5):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200

    kpis = client.get("/api/metrics/kpis", headers=headers)
    assert kpis.status_code == 200
    body = kpis.json()
    assert "open_alerts" in body
    assert "high_severity_alerts" in body
    assert "mttd_minutes" in body
    assert "mttr_minutes" in body
    assert "false_positive_rate" in body

    comparison = client.get("/api/metrics/detection-comparison", headers=headers)
    assert comparison.status_code == 200
    assert "methods" in comparison.json()


def test_paginated_list_responses(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "198.51.100.77",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(6):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200

    events = client.get("/api/events?page=1&page_size=2", headers=headers)
    assert events.status_code == 200
    assert len(events.json()["items"]) == 2
    assert events.json()["pagination"]["total"] >= 6

    alerts = client.get("/api/alerts?page=1&page_size=1", headers=headers)
    assert alerts.status_code == 200
    assert len(alerts.json()["items"]) == 1
    assert alerts.json()["pagination"]["total"] >= 1

    incidents = client.get("/api/incidents?page=1&page_size=10", headers=headers)
    assert incidents.status_code == 200
    assert "items" in incidents.json()
    assert "pagination" in incidents.json()


def test_auth_invalid_credentials_returns_401(client: TestClient):
    response = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_platform_feature_flags_patch_and_audit_log(client: TestClient):
    headers = auth_headers(client)

    list_response = client.get("/api/platform/feature-flags", headers=headers)
    assert list_response.status_code == 200
    flags = list_response.json()
    assert any(flag["key"] == "brute_force_login_rule" for flag in flags)

    patch_response = client.patch(
        "/api/platform/feature-flags/brute_force_login_rule",
        json={"enabled": False},
        headers=headers,
    )
    assert patch_response.status_code == 200
    assert patch_response.json()["enabled"] is False

    missing_patch = client.patch(
        "/api/platform/feature-flags/does_not_exist",
        json={"enabled": True},
        headers=headers,
    )
    assert missing_patch.status_code == 404

    audit_logs = client.get("/api/platform/audit-logs?limit=0", headers=headers)
    assert audit_logs.status_code == 200
    assert any(log["action"] == "feature_flag_updated" for log in audit_logs.json())


def test_alert_assignment_validates_assignee_role(client: TestClient):
    headers = auth_headers(client)

    create_viewer = client.post(
        "/api/events",
        json={
            "source": "identity_provider",
            "source_ip": "198.51.100.80",
            "username": "target-user",
            "event_type": "login_failed",
            "message": "Failed login",
        },
        headers=headers,
    )
    assert create_viewer.status_code == 200
    for _ in range(4):
        client.post(
            "/api/events",
            json={
                "source": "identity_provider",
                "source_ip": "198.51.100.80",
                "username": "target-user",
                "event_type": "login_failed",
                "message": "Failed login",
            },
            headers=headers,
        )

    alert_id = client.get("/api/alerts", headers=headers).json()["items"][0]["id"]
    analysts = client.get("/api/auth/analysts", headers=headers)
    assert analysts.status_code == 200
    assert all(user["role"] in ["Admin", "Analyst"] for user in analysts.json())

    assign_bad = client.patch(
        f"/api/alerts/{alert_id}/assign",
        json={"analyst_id": 999999},
        headers=headers,
    )
    assert assign_bad.status_code == 400
    assert "Assigned analyst" in assign_bad.json()["detail"]

    unassign = client.patch(
        f"/api/alerts/{alert_id}/assign",
        json={"analyst_id": None},
        headers=headers,
    )
    assert unassign.status_code == 200
    assert unassign.json()["assigned_analyst_id"] is None


def test_incident_lifecycle_and_not_found_paths(client: TestClient):
    headers = auth_headers(client)
    for _ in range(5):
        client.post(
            "/api/events",
            json={
                "source": "identity_provider",
                "source_ip": "203.0.113.90",
                "username": "incident-user",
                "event_type": "login_failed",
                "message": "Failed login",
            },
            headers=headers,
        )

    alerts = client.get("/api/alerts", headers=headers).json()["items"]
    alert_id = alerts[0]["id"]

    invalid_incident = client.post(
        "/api/incidents",
        json={"title": "Invalid incident", "summary": "bad", "alert_ids": [999999]},
        headers=headers,
    )
    assert invalid_incident.status_code == 400

    created_incident = client.post(
        "/api/incidents",
        json={"title": "Credential Abuse", "summary": "Escalated auth anomalies", "alert_ids": [alert_id]},
        headers=headers,
    )
    assert created_incident.status_code == 200
    incident_id = created_incident.json()["id"]

    wrapped = client.get(f"/api/incidents/{incident_id}/ai-wrapup", headers=headers)
    assert wrapped.status_code == 200
    assert "Credential Abuse" in wrapped.json()["summary"]

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

    not_found = client.get("/api/incidents/999999", headers=headers)
    assert not_found.status_code == 404


def test_alert_assignment_and_timeline(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "203.0.113.200",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(5):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200

    alert_id = client.get("/api/alerts", headers=headers).json()["items"][0]["id"]
    assign = client.patch(
        f"/api/alerts/{alert_id}/assign",
        json={"analyst_id": 1},
        headers=headers,
    )
    assert assign.status_code == 200
    assert assign.json()["assigned_analyst_id"] == 1

    client.patch(f"/api/alerts/{alert_id}/status", json={"status": "investigating"}, headers=headers)
    client.post(
        f"/api/alerts/{alert_id}/notes",
        json={"note": "Pivoted on source IP and observed recurrence."},
        headers=headers,
    )

    timeline = client.get(f"/api/alerts/{alert_id}/timeline", headers=headers)
    assert timeline.status_code == 200
    actions = [entry["action"] for entry in timeline.json()]
    assert "analyst_assigned" in actions
    assert "status_updated" in actions
    assert "note_added" in actions


def test_incident_grouping_flow(client: TestClient):
    headers = auth_headers(client)
    for source_ip in ["198.51.100.10", "198.51.100.11"]:
        payload = {
            "source": "identity_provider",
            "source_ip": source_ip,
            "username": "jdoe",
            "event_type": "login_failed",
            "message": "Failed login",
        }
        for _ in range(5):
            response = client.post("/api/events", json=payload, headers=headers)
            assert response.status_code == 200

    alert_ids = [item["id"] for item in client.get("/api/alerts", headers=headers).json()["items"][:2]]
    incident = client.post(
        "/api/incidents",
        json={
            "title": "Credential Access Investigation",
            "summary": "Grouped brute force alerts for coordinated triage.",
            "alert_ids": alert_ids,
            "assigned_analyst_id": 1,
        },
        headers=headers,
    )
    assert incident.status_code == 200
    incident_id = incident.json()["id"]

    fetched = client.get(f"/api/incidents/{incident_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["title"] == "Credential Access Investigation"

    closed = client.patch(
        f"/api/incidents/{incident_id}/status",
        json={"status": "closed"},
        headers=headers,
    )
    assert closed.status_code == 200
    assert closed.json()["closed_at"] is not None


def test_known_benign_event_suppression(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "198.51.100.99",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Known scanner validation",
        "metadata": {"known_benign": True},
    }
    for _ in range(6):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200
        assert response.json()["detections"] == []

    alerts = client.get("/api/alerts", headers=headers)
    assert alerts.status_code == 200
    assert alerts.json()["items"] == []


def test_feature_flag_toggle_and_audit_logs(client: TestClient):
    headers = auth_headers(client)
    flags = client.get("/api/platform/feature-flags", headers=headers)
    assert flags.status_code == 200
    assert any(item["key"] == "brute_force_login_rule" for item in flags.json())

    toggle = client.patch(
        "/api/platform/feature-flags/brute_force_login_rule",
        json={"enabled": False},
        headers=headers,
    )
    assert toggle.status_code == 200
    assert toggle.json()["enabled"] is False

    payload = {
        "source": "identity_provider",
        "source_ip": "203.0.113.55",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(6):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200
        assert response.json()["detections"] == []

    logs = client.get("/api/platform/audit-logs", headers=headers)
    assert logs.status_code == 200
    assert any(item["action"] == "feature_flag_updated" for item in logs.json())


def test_ai_assistance_and_feedback_endpoints(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "198.51.100.201",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(5):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200

    alert_id = client.get("/api/alerts", headers=headers).json()["items"][0]["id"]
    summary = client.get(f"/api/alerts/{alert_id}/ai-summary", headers=headers)
    assert summary.status_code == 200
    assert "summary" in summary.json()

    triage = client.get(f"/api/alerts/{alert_id}/ai-triage", headers=headers)
    assert triage.status_code == 200
    assert triage.json()["priority"] in {"P1", "P2", "P3"}

    feedback = client.post(
        f"/api/alerts/{alert_id}/feedback",
        json={"is_true_positive": True, "tuning_notes": "Valid malicious pattern"},
        headers=headers,
    )
    assert feedback.status_code == 200
    assert feedback.json()["is_true_positive"] is True

    incident = client.post(
        "/api/incidents",
        json={"title": "AI Wrapup Test", "summary": "", "alert_ids": [alert_id]},
        headers=headers,
    )
    assert incident.status_code == 200
    incident_id = incident.json()["id"]
    wrapup = client.get(f"/api/incidents/{incident_id}/ai-wrapup", headers=headers)
    assert wrapup.status_code == 200
    assert "Incident" in wrapup.json()["summary"]


def test_detection_background_job_flow(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "203.0.113.250",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }

    for _ in range(6):
        response = client.post("/api/events?defer_detection=true", json=payload, headers=headers)
        assert response.status_code == 200
        assert response.json()["detections"] == []
        assert response.json()["job_id"] is not None

    before = client.get("/api/alerts", headers=headers)
    assert before.status_code == 200
    assert before.json()["items"] == []

    jobs = client.get("/api/jobs", headers=headers)
    assert jobs.status_code == 200
    assert any(item["status"] == "queued" for item in jobs.json())

    process = client.post("/api/jobs/process-pending", headers=headers)
    assert process.status_code == 200
    assert all(item["status"] in {"completed", "failed"} for item in process.json())

    after = client.get("/api/alerts", headers=headers)
    assert after.status_code == 200
    assert len(after.json()["items"]) >= 1

    job_metrics = client.get("/api/metrics/jobs", headers=headers)
    assert job_metrics.status_code == 200
    assert "completed" in job_metrics.json()


def test_detection_quality_and_scenario_benchmarks(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "198.51.100.31",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(5):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200

    alert_id = client.get("/api/alerts", headers=headers).json()["items"][0]["id"]
    feedback = client.post(
        f"/api/alerts/{alert_id}/feedback",
        json={"is_true_positive": False, "tuning_notes": "Likely false positive"},
        headers=headers,
    )
    assert feedback.status_code == 200

    quality = client.get("/api/metrics/detection-quality", headers=headers)
    assert quality.status_code == 200
    assert quality.json()["reviewed_alerts"] >= 1
    assert "precision" in quality.json()

    seed = client.post(
        "/api/events/scenarios/identity_privilege_escalation/seed",
        headers=headers,
    )
    assert seed.status_code == 200

    benchmarks = client.get("/api/metrics/scenario-benchmarks", headers=headers)
    assert benchmarks.status_code == 200
    assert any(item["scenario"] == "identity_privilege_escalation" for item in benchmarks.json())


def test_batch_event_ingest_generates_detections_and_alerts(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "events": [
            {
                "source": "identity_provider",
                "source_ip": "198.51.100.222",
                "username": "jdoe",
                "event_type": "login_failed",
                "message": "Failed login",
            }
            for _ in range(6)
        ]
    }
    response = client.post("/api/events/batch", json=payload, headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["events_ingested"] == 6
    assert body["detections_generated"] >= 1
    assert body["alerts_generated"] >= 1
    assert len(body["job_ids"]) == 6


def test_batch_event_ingest_deferred_processing(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "defer_detection": True,
        "events": [
            {
                "source": "identity_provider",
                "source_ip": "203.0.113.88",
                "username": "jdoe",
                "event_type": "login_failed",
                "message": "Failed login",
            }
            for _ in range(6)
        ],
    }
    response = client.post("/api/events/batch", json=payload, headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["events_ingested"] == 6
    assert body["detections_generated"] == 0
    assert body["alerts_generated"] == 0

    alerts_before = client.get("/api/alerts", headers=headers)
    assert alerts_before.status_code == 200
    assert alerts_before.json()["items"] == []

    process = client.post("/api/jobs/process-pending", headers=headers)
    assert process.status_code == 200

    alerts_after = client.get("/api/alerts", headers=headers)
    assert alerts_after.status_code == 200
    assert len(alerts_after.json()["items"]) >= 1


def test_list_analysts_endpoint(client: TestClient):
    headers = auth_headers(client)
    response = client.get("/api/auth/analysts", headers=headers)
    assert response.status_code == 200
    usernames = {item["username"] for item in response.json()}
    assert "admin" in usernames


def test_threat_intel_match_detection(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "firewall",
        "source_ip": "203.0.113.44",
        "event_type": "connection_allowed",
        "message": "Outbound connection to suspicious destination",
        "metadata": {"threat_intel_match": True, "ioc": "203.0.113.44"},
    }
    response = client.post("/api/events", json=payload, headers=headers)
    assert response.status_code == 200
    detection_types = {item["detection_type"] for item in response.json()["detections"]}
    assert "threat_intel_match_indicator" in detection_types


def test_impossible_travel_detection(client: TestClient):
    headers = auth_headers(client)
    first_payload = {
        "source": "vpn_gateway",
        "username": "analyst",
        "source_ip": "198.51.100.8",
        "event_type": "login_success",
        "message": "Successful login from US",
        "metadata": {"geolocation": "US"},
    }
    second_payload = {
        "source": "vpn_gateway",
        "username": "analyst",
        "source_ip": "203.0.113.8",
        "event_type": "login_success",
        "message": "Successful login from DE",
        "metadata": {"geolocation": "DE"},
    }
    first = client.post("/api/events", json=first_payload, headers=headers)
    assert first.status_code == 200
    second = client.post("/api/events", json=second_payload, headers=headers)
    assert second.status_code == 200
    detection_types = {item["detection_type"] for item in second.json()["detections"]}
    assert "impossible_travel_login_anomaly" in detection_types


def test_correlation_hotspots_metric(client: TestClient):
    headers = auth_headers(client)
    payload = {
        "source": "identity_provider",
        "source_ip": "198.51.100.77",
        "username": "jdoe",
        "event_type": "login_failed",
        "message": "Failed login",
    }
    for _ in range(6):
        response = client.post("/api/events", json=payload, headers=headers)
        assert response.status_code == 200

    metrics = client.get("/api/metrics/correlation-hotspots", headers=headers)
    assert metrics.status_code == 200
    rows = metrics.json()
    assert len(rows) >= 1
    assert rows[0]["max_dedup_count"] >= 1
