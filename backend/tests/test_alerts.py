from datetime import datetime


def login(client) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin123"},
    )
    return response.json()["access_token"]


def test_alert_status_update(client):
    token = login(client)
    client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "event_type": "role_change",
            "source_ip": "10.2.3.4",
            "actor": "bob",
            "severity": "high",
            "occurred_at": datetime.utcnow().isoformat(),
            "payload": {},
        },
    )

    alerts = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"}).json()
    alert_id = alerts[0]["id"]
    response = client.patch(
        f"/api/v1/alerts/{alert_id}/status",
        headers={"Authorization": f"Bearer {token}"},
        json={"status": "investigating"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "investigating"
