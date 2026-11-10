from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_health():
    assert client.get("/health").json()["status"] == "ok"

def test_tool_catalog():
    response = client.get("/v1/tools")
    assert response.status_code == 200
    assert response.json()["integrations_catalogued"] == 27

def test_job_requires_authorization():
    response = client.post("/v1/jobs/plan", json={
        "asset_id": "asset-123456", "tool_key": "semgrep",
        "mode": "static", "authorization_confirmed": False
    })
    assert response.status_code == 403

def test_active_job_requires_approval():
    response = client.post("/v1/jobs/plan", json={
        "asset_id": "asset-123456", "tool_key": "nmap",
        "mode": "active", "authorization_confirmed": True
    })
    assert response.status_code == 200
    assert response.json()["status"] == "approval_required"
