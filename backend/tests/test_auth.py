def test_demo_login_success(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "analyst123"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert body["role"] == "analyst"


def test_demo_login_failure(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "wrong"},
    )
    assert response.status_code == 401
