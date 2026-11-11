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
    assert response.json()["workflow_enabled"] == 11
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


def test_public_config_exposes_only_publishable_supabase_settings(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "sb_publishable_test_public_key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "must-never-be-returned")
    response = client.get("/v1/config")
    assert response.status_code == 200
    data = response.json()
    assert data["supabase_url"] == "https://example.supabase.co"
    assert data["supabase_publishable_key"] == "sb_publishable_test_public_key"
    assert data["ai_enabled"] is False
    assert "must-never-be-returned" not in response.text


def test_ai_advisory_uses_free_openrouter_model(monkeypatch):
    authenticated_user()
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")
    calls = []

    class Response:
        status_code = 200
        def json(self):
            return {
                "model": "cohere/north-mini-code:free",
                "choices": [{"message": {"content": "تحقق من صلاحيات الوصول وسجلات التطبيق."}}]
            }

    def fake_post(url, **kwargs):
        calls.append(kwargs["json"]["model"])
        return Response()

    monkeypatch.setattr(main.httpx, "post", fake_post)
    response = client.post("/v1/assistant/review", json={
        "question": "راجع إعدادات أمان التطبيق.",
        "context": "لا توجد نتائج فحص مرفقة."
    })
    assert response.status_code == 200
    assert response.json()["provider"] == "OpenRouter"
    assert response.json()["execution_enabled"] is False
    assert calls == ["cohere/north-mini-code:free"]


def test_ai_advisory_falls_back_to_second_free_model(monkeypatch):
    authenticated_user()
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-openrouter-key")
    calls = []

    class Response:
        def __init__(self, status_code, payload):
            self.status_code = status_code
            self.payload = payload
        def json(self):
            return self.payload

    def fake_post(url, **kwargs):
        model = kwargs["json"]["model"]
        calls.append(model)
        if len(calls) == 1:
            return Response(429, {})
        return Response(200, {
            "model": "nvidia/nemotron-3.5-lightning:free",
            "choices": [{"message": {"content": "راجع إعدادات TLS."}}]
        })

    monkeypatch.setattr(main.httpx, "post", fake_post)
    response = client.post("/v1/assistant/review", json={
        "question": "حلل إعدادات TLS.",
        "context": ""
    })
    assert response.status_code == 200
    assert response.json()["fallback_used"] is True
    assert calls == ["cohere/north-mini-code:free", "nvidia/nemotron-3.5-lightning:free"]


def test_ai_advisory_requires_server_side_key(monkeypatch):
    authenticated_user()
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    response = client.post("/v1/assistant/review", json={
        "question": "حلل هذا التقرير الأمني.",
        "context": ""
    })
    assert response.status_code == 503


def test_supabase_auth_does_not_require_service_role_key(monkeypatch):
    from fastapi.security import HTTPAuthorizationCredentials
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "sb_publishable_test_public_key")
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)

    class Response:
        status_code = 200
        def json(self):
            return {"id": "user-12345678"}

    monkeypatch.setattr(main.httpx, "get", lambda *args, **kwargs: Response())
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="user-access-token")
    assert main.current_user(credentials) == {"id": "user-12345678"}


@pytest.mark.parametrize("status_code", [200, 204])
def test_dispatch_accepts_documented_github_success_codes(monkeypatch, status_code):
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")

    class Response:
        def __init__(self, code):
            self.status_code = code

    calls = []
    def fake_post(url, **kwargs):
        calls.append((url, kwargs["json"]))
        return Response(status_code)

    monkeypatch.setattr(main.httpx, "post", fake_post)
    main._dispatch_static("job-12345678")
    assert calls[0][1]["inputs"]["job_id"] == "job-12345678"


def test_only_verified_source_and_apk_scanners_are_advertised_as_api_enabled():
    response = client.get("/v1/tools")
    tools = response.json()["tools"]
    enabled = {key for key, item in tools.items() if item["workflow_enabled"]}
    assert enabled == {"semgrep", "gitleaks", "trivy", "checkov", "grype", "syft", "yara", "clamav", "mobsf", "jadx", "apktool"}
    assert tools["nmap"]["execution_available"] is False
    assert tools["mobsf"]["execution_available"] is True


def test_apk_upload_requires_valid_filename_and_authorization(monkeypatch):
    authenticated_user()
    response = client.post(
        "/v1/apks/upload?file_name=not-a-file.txt&authorization_note=I+own+this+application+and+authorize+testing.&authorization_confirmed=true",
        content=bytes.fromhex("504b0304") + b"test",
        headers={"Content-Type":"application/octet-stream"},
    )
    assert response.status_code == 400


def test_apk_upload_rejects_missing_explicit_confirmation(monkeypatch):
    authenticated_user()
    response = client.post(
        "/v1/apks/upload?file_name=sample.apk&authorization_note=I+own+this+APK+and+authorize+testing.&authorization_confirmed=false",
        content=bytes.fromhex("504b0304") + b"test",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 403


def test_apk_upload_requires_authorization_note(monkeypatch):
    authenticated_user()
    response = client.post(
        "/v1/apks/upload?file_name=sample.apk&authorization_note=short&authorization_confirmed=true",
        content=bytes.fromhex("504b0304") + b"test",
        headers={"Content-Type":"application/octet-stream"},
    )
    assert response.status_code == 400


def test_apk_upload_stores_private_asset_and_dispatches_analysis(monkeypatch):
    authenticated_user()
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_ANON_KEY", "public-test-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "server-test-key")
    monkeypatch.setenv("GITHUB_TOKEN", "github-test-token")

    class Response:
        def __init__(self, payload, status_code=200):
            self.payload = payload
            self.status_code = status_code
        def json(self):
            return self.payload
        def raise_for_status(self):
            if self.status_code >= 400:
                raise main.httpx.HTTPStatusError("failed", request=None, response=None)

    def fake_get(url, **kwargs):
        if url.endswith("/workspaces"):
            return Response([{"id": "workspace-123456"}])
        raise AssertionError(url)

    def fake_post(url, **kwargs):
        if "/storage/v1/object/apk-uploads/" in url:
            return Response({}, 200)
        if url.endswith("/rest/v1/assets"):
            return Response([{"id": "asset-123456"}], 201)
        if "/storage/v1/object/sign/apk-uploads/" in url:
            return Response({"signedURL": "/object/sign/apk-uploads/user-12345678/test/sample.apk?token=temporary"})
        if url.endswith("/rest/v1/analysis_jobs"):
            return Response([{"id": "job-12345678"}], 201)
        raise AssertionError(url)

    dispatched = []
    monkeypatch.setattr(main.httpx, "get", fake_get)
    monkeypatch.setattr(main.httpx, "post", fake_post)
    monkeypatch.setattr(main, "_dispatch_apk", lambda *args: dispatched.append(args))
    monkeypatch.setattr(main, "_audit", lambda *_: None)

    response = client.post(
        "/v1/apks/upload?file_name=sample.apk&authorization_note=I+own+this+APK+and+authorize+static+security+analysis.&authorization_confirmed=true",
        content=bytes.fromhex("504b0304") + b"sample-apk-bytes",
        headers={"Content-Type": "application/vnd.android.package-archive"},
    )
    assert response.status_code == 200
    assert response.json()["job_id"] == "job-12345678"
    assert dispatched[0][0] == "job-12345678"
    assert dispatched[0][1].startswith("https://example.supabase.co/storage/v1/object/sign/")
    assert dispatched[0][2] == "sample.apk"
