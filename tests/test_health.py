"""Checks: the app starts, serves the API and serves the frontend."""

from fastapi.testclient import TestClient

from backend.main import app


def test_health_returns_ok():
    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_index_serves_frontend():
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Canary Records" in response.text


def test_static_assets_are_served():
    with TestClient(app) as client:
        css = client.get("/static/styles.css")
        js = client.get("/static/app.js")

    assert css.status_code == 200
    assert js.status_code == 200


def test_health_response_contains_no_configuration_values():
    """The health endpoint must not leak settings or secrets."""
    with TestClient(app) as client:
        payload = client.get("/api/health").json()

    assert set(payload) == {"status"}
