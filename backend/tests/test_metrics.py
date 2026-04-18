from datetime import datetime


def token(client) -> str:
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "analyst123"},
    )
    return response.json()["access_token"]


def test_metrics_summary(client):
    access_token = token(client)
    client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "event_type": "access_denied",
            "source_ip": "10.4.4.4",
            "actor": "svc-account",
            "severity": "medium",
            "occurred_at": datetime.utcnow().isoformat(),
            "payload": {"failed_access_count": 25},
        },
    )

    response = client.get("/api/v1/metrics/summary", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["events_24h"] >= 1
    assert payload["alerts_open"] >= 1
