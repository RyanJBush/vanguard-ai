from datetime import datetime


def get_token(client) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "analyst123"},
    )
    return response.json()["access_token"]


def test_event_ingestion_creates_alert(client):
    token = get_token(client)
    response = client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "event_type": "failed_login",
            "source_ip": "10.0.0.1",
            "actor": "alice",
            "severity": "medium",
            "occurred_at": datetime.utcnow().isoformat(),
            "payload": {"failed_count": 7, "host": "srv-01"},
        },
    )
    assert response.status_code == 200

    alerts_response = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
    assert alerts_response.status_code == 200
    assert len(alerts_response.json()) >= 1
