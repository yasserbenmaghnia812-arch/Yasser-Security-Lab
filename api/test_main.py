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
    assert response.json()["workflow_enabled"] == 26
    assert response.json()["api_dispatch_enabled"] is False
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
    assert response.json()["status"] == "workflow_available"
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


def test_static_dispatch_creates_and_dispatches_job(monkeypatch):
    authenticated_user()
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(main, "load_authorized_asset", lambda *_: {
        "id": "asset-123456", "workspace_id": "workspace-123",
        "asset_type": "source", "identifier": "yasser-security-lab",
        "authorization_confirmed": True, "allowed_tests": ["static"], "expires_at": None
    })
    monkeypatch.setattr(main, "_insert_job", lambda *_: {"id": "job-12345678"})
    dispatched = []
    monkeypatch.setattr(main, "_dispatch_static", lambda job_id: dispatched.append(job_id))
    monkeypatch.setattr(main, "_audit", lambda *_: None)
    response = client.post("/v1/jobs/dispatch", json={
        "asset_id": "asset-123456", "tool_key": "semgrep", "mode": "static"
    })
    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    assert dispatched == ["job-12345678"]


def test_api_does_not_dispatch_active_or_apk_jobs(monkeypatch):
    authenticated_user()
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(main, "load_authorized_asset", lambda *_: {
        "id": "asset-123456", "workspace_id": "workspace-123",
        "asset_type": "apk", "identifier": "sample.apk",
        "authorization_confirmed": True, "allowed_tests": ["active", "reverse_engineering"], "expires_at": None
    })
    response = client.post("/v1/jobs/dispatch", json={
        "asset_id": "asset-123456", "tool_key": "nmap", "mode": "active"
    })
    assert response.status_code == 403


def test_source_asset_registration_requires_explicit_attestation(monkeypatch):
    authenticated_user()
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "public-test-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "server-test-key")

    class Response:
        def __init__(self, payload):
            self.payload = payload
        def json(self):
            return self.payload
        def raise_for_status(self):
            return None

    def fake_get(url, **kwargs):
        if url.endswith("/workspaces"):
            return Response([])
        if url.endswith("/assets"):
            return Response([])
        raise AssertionError(url)

    def fake_post(url, **kwargs):
        if url.endswith("/workspaces"):
            return Response([{"id": "workspace-123456"}])
        if url.endswith("/assets"):
            return Response([{"id": "asset-123456"}])
        raise AssertionError(url)

    monkeypatch.setattr(main.httpx, "get", fake_get)
    monkeypatch.setattr(main.httpx, "post", fake_post)
    response = client.post("/v1/assets/register", json={
        "authorization_confirmed": True,
        "authorization_note": "I own this repository and authorize static analysis."
    })
    assert response.status_code == 200
    assert response.json()["asset_id"] == "asset-123456"
    assert response.json()["allowed_tests"] == ["static"]
