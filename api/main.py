import os
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

app = FastAPI(title="Yasser Security Lab API", version="0.2.0")
security = HTTPBearer(auto_error=False)

origins = [item.strip() for item in os.getenv("ALLOWED_ORIGINS", "").split(",") if item.strip()]
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "apikey"],
    )


class Mode(str, Enum):
    passive = "passive"
    active = "active"
    static = "static"
    reverse_engineering = "reverse_engineering"


class JobPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=8, max_length=80)
    tool_key: str = Field(min_length=2, max_length=40)
    mode: Mode
    parameters: dict[str, Any] = Field(default_factory=dict)


TOOLS = {
    "nmap": {"mode": "active", "description": "Approved network inventory"},
    "zap": {"mode": "active", "description": "Authorized web application assessment"},
    "nuclei": {"mode": "active", "description": "Curated non-destructive template checks"},
    "semgrep": {"mode": "static", "description": "Source code analysis"},
    "gitleaks": {"mode": "static", "description": "Secret scanning"},
    "trivy": {"mode": "static", "description": "Dependency and image scanning"},
    "mobsf": {"mode": "reverse_engineering", "description": "Mobile application analysis"},
    "jadx": {"mode": "reverse_engineering", "description": "APK/DEX inspection"},
    "apktool": {"mode": "reverse_engineering", "description": "APK resource inspection"},
    "androguard": {"mode": "reverse_engineering", "description": "Android static analysis"},
    "ghidra": {"mode": "reverse_engineering", "description": "Authorized binary analysis"},
    "yara": {"mode": "static", "description": "Static malware pattern matching"},
    "clamav": {"mode": "static", "description": "Malware file scanning"},
}


def _config() -> tuple[str, str, str]:
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    anon_key = os.getenv("SUPABASE_ANON_KEY", "")
    service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    if not url or not anon_key or not service_key:
        raise HTTPException(status_code=503, detail="Supabase server configuration is incomplete.")
    return url, anon_key, service_key


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="A valid Supabase access token is required.")
    url, anon_key, _ = _config()
    try:
        response = httpx.get(
            f"{url}/auth/v1/user",
            headers={"apikey": anon_key, "Authorization": f"Bearer {credentials.credentials}"},
            timeout=10.0,
        )
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Supabase Auth is temporarily unreachable.")
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Supabase access token is invalid or expired.")
    user = response.json()
    if not isinstance(user, dict) or not user.get("id"):
        raise HTTPException(status_code=401, detail="Supabase did not return a valid user.")
    return user


def load_authorized_asset(asset_id: str, user_id: str) -> dict[str, Any]:
    url, _, service_key = _config()
    headers = {
        "apikey": service_key,
        "Authorization": f"Bearer {service_key}",
    }
    try:
        asset_response = httpx.get(
            f"{url}/rest/v1/assets",
            params={"id": f"eq.{asset_id}", "select": "id,workspace_id,identifier,authorization_confirmed,allowed_tests,expires_at"},
            headers=headers,
            timeout=10.0,
        )
        asset_response.raise_for_status()
        assets = asset_response.json()
        if not assets:
            raise HTTPException(status_code=404, detail="Asset was not found.")
        asset = assets[0]
        workspace_response = httpx.get(
            f"{url}/rest/v1/workspaces",
            params={"id": f"eq.{asset['workspace_id']}", "owner_id": f"eq.{user_id}", "select": "id"},
            headers=headers,
            timeout=10.0,
        )
        workspace_response.raise_for_status()
        if not workspace_response.json():
            raise HTTPException(status_code=404, detail="Asset was not found in your workspace.")
        return asset
    except HTTPException:
        raise
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Could not verify the asset scope in Supabase.")


@app.get("/health")
def health():
    return {"status": "ok", "service": "yasser-security-lab-api"}


@app.get("/v1/tools")
def list_tools():
    return {"tools": TOOLS, "integrations_catalogued": 27, "execution_enabled": False}


@app.post("/v1/jobs/plan")
def plan_job(job: JobPlan, user: dict[str, Any] = Depends(current_user)):
    if job.tool_key not in TOOLS:
        raise HTTPException(status_code=400, detail="Tool adapter is not enabled.")
    required_mode = TOOLS[job.tool_key]["mode"]
    if job.mode.value != required_mode:
        raise HTTPException(status_code=400, detail="Requested mode does not match this adapter.")

    asset = load_authorized_asset(job.asset_id, user["id"])
    if not asset.get("authorization_confirmed"):
        raise HTTPException(status_code=403, detail="This asset has not been verified by the server.")
    expires_at = asset.get("expires_at")
    if expires_at:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expiry <= datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="The asset authorization has expired.")
    allowed_tests = asset.get("allowed_tests") or []
    if job.mode.value not in allowed_tests:
        raise HTTPException(status_code=403, detail="This test mode is outside the approved asset scope.")

    if job.mode == Mode.active:
        return {
            "status": "approval_required",
            "plan_only": True,
            "message": "Active assessment requires a separate server-recorded approval. No scan was started.",
        }

    return {
        "status": "planned",
        "plan_only": True,
        "execution_enabled": False,
        "tool": job.tool_key,
        "mode": job.mode.value,
        "asset": asset["identifier"],
        "message": "Scope verified. Scanner execution is not enabled in this API release.",
    }
