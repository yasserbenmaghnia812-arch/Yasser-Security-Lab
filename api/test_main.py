import pytest
from fastapi.testclient import TestClient

import main

client = TestClient(main.app)


@pytest.fixture(autouse=True)
def clear_overrides():
    main.app.dependency_overrides.clear()
    yield
    main.app.dependency_overrides.clear()


def authenticated_user():
    main.app.dependency_overrides[main.current_user] = lambda: {"id": "user-12345678"}


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_tool_catalog_is_plan_only():
    response = client.get("/v1/tools")
    assert response.status_code == 200
    assert response.json()["integrations_catalogued"] == 27
    assert response.json()["execution_enabled"] is False


def test_job_requires_supabase_auth():
    response = client.post("/v1/jobs/plan", json={
        "asset_id": "asset-123456", "tool_key": "semgrep", "mode": "static"
    })
    assert response.status_code == 401


def test_asset_must_be_server_verified(monkeypatch):
    authenticated_user()
    monkeypatch.setattr(main, "load_authorized_asset", lambda *_: {
        "identifier": "owned.example", "authorization_confirmed": False,
        "allowed_tests": ["passive"], "expires_at": None
    })
    response = client.post("/v1/jobs/plan", json={
        "asset_id": "asset-123456", "tool_key": "semgrep", "mode": "static"
    })
    assert response.status_code == 403


def test_static_plan_requires_approved_scope(monkeypatch):
    authenticated_user()
    monkeypatch.setattr(main, "load_authorized_asset", lambda *_: {
        "identifier": "owned.example", "authorization_confirmed": True,
        "allowed_tests": ["static"], "expires_at": None
    })
    response = client.post("/v1/jobs/plan", json={
        "asset_id": "asset-123456", "tool_key": "semgrep", "mode": "static"
    })
    assert response.status_code == 200
    assert response.json()["status"] == "planned"
    assert response.json()["execution_enabled"] is False


def test_active_job_never_starts_from_plan_endpoint(monkeypatch):
    authenticated_user()
    monkeypatch.setattr(main, "load_authorized_asset", lambda *_: {
        "identifier": "owned.example", "authorization_confirmed": True,
        "allowed_tests": ["active"], "expires_at": None
    })
    response = client.post("/v1/jobs/plan", json={
        "asset_id": "asset-123456", "tool_key": "nmap", "mode": "active"
    })
    assert response.status_code == 200
    assert response.json()["status"] == "approval_required"
    assert response.json()["plan_only"] is True
