import asyncio
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

from tool_registry import TOOL_REGISTRY, public_tool_catalog

app = FastAPI(title="Yasser Security Lab API", version="0.3.0")
security = HTTPBearer(auto_error=False)
REPOSITORY = os.getenv("GITHUB_REPOSITORY", "yasserbenmaghnia812-arch/Yasser-Security-Lab")
STATIC_WORKFLOW = "security-static.yml"
APK_WORKFLOW = "apk-analysis-api.yml"
APK_BUCKET = "apk-uploads"
MAX_APK_BYTES = 150 * 1024 * 1024
APK_ZIP_SIGNATURE = bytes.fromhex("504b0304")
STATIC_TOOLS = {"full-static-suite"}

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
    user_approved: bool = False


class SourceAssetRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_name: str = Field(default="Yasser Security Lab", min_length=1, max_length=100)
    authorization_confirmed: bool
    authorization_note: str = Field(min_length=12, max_length=2000)


class AssistantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=5, max_length=4000)
    context: str = Field(default="", max_length=5000)


class AgentTaskType(str, Enum):
    api_tests = "api_tests"
    android_debug_apk = "android_debug_apk"


class AgentTaskPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_type: AgentTaskType


class AgentTaskExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task_type: AgentTaskType
    user_approved: bool = False


TOOLS = TOOL_REGISTRY


def _auth_config() -> tuple[str, str]:
    url = os.getenv("SUPABASE_URL", "").rstrip("/")
    anon_key = os.getenv("SUPABASE_ANON_KEY", "")
    if not url or not anon_key:
        raise HTTPException(status_code=503, detail="Supabase public authentication configuration is incomplete.")
    return url, anon_key


def _config() -> tuple[str, str, str]:
    url, anon_key = _auth_config()
    service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    if not service_key:
        raise HTTPException(status_code=503, detail="Supabase server configuration is incomplete.")
    return url, anon_key, service_key


def _service_headers(service_key: str, prefer: str | None = None) -> dict[str, str]:
    headers = {"apikey": service_key, "Authorization": f"Bearer {service_key}", "Content-Type": "application/json"}
    if prefer:
        headers["Prefer"] = prefer
    return headers


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="A valid Supabase access token is required.")
    url, anon_key = _auth_config()
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
    headers = _service_headers(service_key)
    try:
        asset_response = httpx.get(
            f"{url}/rest/v1/assets",
            params={"id": f"eq.{asset_id}", "select": "id,workspace_id,asset_type,identifier,authorization_confirmed,allowed_tests,expires_at"},
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


def _assert_asset_authorized(asset: dict[str, Any], mode: Mode) -> None:
    if not asset.get("authorization_confirmed"):
        raise HTTPException(status_code=403, detail="This asset has not been verified by the server.")
    expires_at = asset.get("expires_at")
    if expires_at:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if expiry <= datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="The asset authorization has expired.")
    if mode.value not in (asset.get("allowed_tests") or []):
        raise HTTPException(status_code=403, detail="This test mode is outside the approved asset scope.")


def _insert_job(job: JobPlan, asset: dict[str, Any], user_id: str) -> dict[str, Any]:
    url, _, service_key = _config()
    payload = {
        "workspace_id": asset["workspace_id"],
        "asset_id": asset["id"],
        "requested_by": user_id,
        "tool_key": job.tool_key,
        "mode": job.mode.value,
        "status": "queued",
        "approved_at": datetime.now(timezone.utc).isoformat() if job.user_approved else None,
        "approved_by": user_id if job.user_approved else None,
        "parameters": job.parameters,
    }
    try:
        response = httpx.post(
            f"{url}/rest/v1/analysis_jobs",
            json=payload,
            headers=_service_headers(service_key, "return=representation"),
            timeout=15.0,
        )
        response.raise_for_status()
        rows = response.json()
        if not rows:
            raise HTTPException(status_code=503, detail="Supabase did not return the queued job.")
        return rows[0]
    except HTTPException:
        raise
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Could not create the analysis job in Supabase.")


def _audit(workspace_id: str, user_id: str, job_id: str, event_type: str) -> None:
    url, _, service_key = _config()
    try:
        response = httpx.post(
            f"{url}/rest/v1/audit_events",
            json={"workspace_id": workspace_id, "actor_id": user_id, "event_type": event_type, "object_id": job_id},
            headers=_service_headers(service_key, "return=minimal"),
            timeout=10.0,
        )
        response.raise_for_status()
    except httpx.HTTPError:
        # Audit failure is surfaced in service logs; it must not leak privileged details.
        logging.getLogger(__name__).warning("Audit write failed for job %s", job_id)


def _dispatch_apk(job_id: str, download_url: str, file_name: str) -> None:
    token = os.getenv("GITHUB_TOKEN", "")
    if not token:
        raise HTTPException(status_code=503, detail="GitHub Actions dispatch is not configured on the API service.")
    endpoint = f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/{APK_WORKFLOW}/dispatches"
    headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"}
    try:
        response = httpx.post(endpoint, headers=headers, json={"ref":"main","inputs":{"job_id":job_id,"download_url":download_url,"file_name":file_name}}, timeout=20.0)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="GitHub Actions could not be reached.")
    if response.status_code not in (200, 204):
        raise HTTPException(status_code=502, detail="GitHub rejected the APK analysis workflow dispatch.")


def _dispatch_static(job_id: str) -> None:
    token = os.getenv("GITHUB_TOKEN", "")
    if not token:
        raise HTTPException(status_code=503, detail="GitHub Actions dispatch is not configured on the API service.")
    endpoint = f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/{STATIC_WORKFLOW}/dispatches"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        response = httpx.post(
            endpoint,
            headers=headers,
            json={"ref": "main", "inputs": {"confirm_owned_files": "true", "job_id": job_id}},
            timeout=20.0,
        )
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="GitHub Actions could not be reached.")
    # GitHub documents 200 for workflow_dispatch responses; accept 204 for older-compatible responses.
    if response.status_code not in (200, 204):
        raise HTTPException(status_code=502, detail="GitHub rejected the workflow dispatch. Check the Actions permission on the API token.")


def _get_job(job_id: str, user_id: str) -> dict[str, Any]:
    url, _, service_key = _config()
    try:
        response = httpx.get(
            f"{url}/rest/v1/analysis_jobs",
            params={"id": f"eq.{job_id}", "requested_by": f"eq.{user_id}", "select": "id,workspace_id,asset_id,tool_key,mode,status,created_at,started_at,finished_at"},
            headers=_service_headers(service_key),
            timeout=10.0,
        )
        response.raise_for_status()
        rows = response.json()
        if not rows:
            raise HTTPException(status_code=404, detail="Job was not found.")
        return rows[0]
    except HTTPException:
        raise
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Could not retrieve the job from Supabase.")


def _find_github_run(job_id: str, mode: str = "static") -> dict[str, Any] | None:
    token = os.getenv("GITHUB_TOKEN", "")
    if not token:
        return None
    workflow = APK_WORKFLOW if mode == "reverse_engineering" else STATIC_WORKFLOW
    url = f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/{workflow}/runs"
    try:
        response = httpx.get(
            url,
            params={"per_page": 100, "branch": "main"},
            headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"},
            timeout=15.0,
        )
        response.raise_for_status()
        expected = f"API job {job_id}"
        return next((run for run in response.json().get("workflow_runs", []) if run.get("display_title") == expected), None)
    except httpx.HTTPError:
        return None


def _sync_job_status(job: dict[str, Any], run: dict[str, Any] | None) -> dict[str, Any]:
    if not run:
        return {**job, "github_run": None}
    state = run.get("status")
    conclusion = run.get("conclusion")
    mapped = "running" if state == "in_progress" else "queued" if state == "queued" else (
        "succeeded" if conclusion == "success" else "failed" if conclusion else job["status"]
    )
    if mapped != job["status"]:
        url, _, service_key = _config()
        patch = {"status": mapped}
        if mapped == "running" and not job.get("started_at"):
            patch["started_at"] = datetime.now(timezone.utc).isoformat()
        if mapped in {"succeeded", "failed"}:
            patch["finished_at"] = datetime.now(timezone.utc).isoformat()
        try:
            httpx.patch(
                f"{url}/rest/v1/analysis_jobs",
                params={"id": f"eq.{job['id']}"},
                json=patch,
                headers=_service_headers(service_key, "return=minimal"),
                timeout=10.0,
            ).raise_for_status()
        except httpx.HTTPError:
            pass
    return {
        **job,
        "status": mapped,
        "github_run": {
            "id": run.get("id"),
            "url": run.get("html_url"),
            "status": state,
            "conclusion": conclusion,
        },
    }


@app.get("/v1/config")
def public_config():
    supabase_url = os.getenv("SUPABASE_URL", "").rstrip("/")
    publishable_key = os.getenv("SUPABASE_ANON_KEY", "")
    if not supabase_url or not publishable_key:
        raise HTTPException(status_code=503, detail="Public client configuration is not available.")
    return {
        "supabase_url": supabase_url,
        "supabase_publishable_key": publishable_key,
        "ai_enabled": bool(os.getenv("OPENROUTER_API_KEY")),
        "ai_model": os.getenv("OPENROUTER_MODEL", "cohere/north-mini-code:free"),
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "yasser-security-lab-api"}


AGENT_TASKS = {
    AgentTaskType.api_tests: {
        "title": "تشغيل اختبارات API",
        "steps": ["تثبيت متطلبات Python", "تشغيل pytest -q داخل api/", "حفظ سجل GitHub Actions"],
    },
    AgentTaskType.android_debug_apk: {
        "title": "بناء APK تجريبي",
        "steps": ["إعداد Java 17 وAndroid SDK", "تشغيل Gradle assembleDebug", "رفع APK كـ GitHub Actions artifact"],
    },
}


@app.post("/v1/agent/plan")
def plan_agent_task(request: AgentTaskPlanRequest, user: dict[str, Any] = Depends(current_user)):
    task = AGENT_TASKS[request.task_type]
    return {
        "task_type": request.task_type.value,
        "title": task["title"],
        "steps": task["steps"],
        "requires_approval": True,
        "execution_enabled": False,
        "message": "هذه معاينة فقط. لن يبدأ أي تشغيل حتى ترسل طلب التنفيذ مع user_approved=true.",
    }


@app.post("/v1/agent/execute")
def execute_agent_task(request: AgentTaskExecutionRequest, user: dict[str, Any] = Depends(current_user)):
    if request.user_approved is not True:
        raise HTTPException(status_code=403, detail="Explicit per-task approval is required.")
    token = os.getenv("GITHUB_TOKEN", "")
    if not token:
        raise HTTPException(status_code=503, detail="GitHub Actions dispatch is not configured on the API service.")
    request_id = __import__("uuid").uuid4().hex
    endpoint = f"https://api.github.com/repos/{REPOSITORY}/actions/workflows/agent-approved-task.yml/dispatches"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        response = httpx.post(
            endpoint,
            headers=headers,
            json={
                "ref": os.getenv("AGENT_WORKFLOW_REF", "main"),
                "inputs": {
                    "task_type": request.task_type.value,
                    "approval_confirmed": "true",
                    "request_id": request_id,
                },
            },
            timeout=20.0,
        )
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="GitHub Actions could not be reached.")
    if response.status_code not in (200, 204):
        raise HTTPException(status_code=502, detail="GitHub rejected the approved agent task.")
    logging.getLogger(__name__).info("Approved agent task dispatched: %s (%s)", request.task_type.value, request_id)
    return {
        "status": "queued",
        "request_id": request_id,
        "task_type": request.task_type.value,
        "workflow": "agent-approved-task.yml",
        "message": "GitHub Actions accepted the approved task. Check the workflow run for the final result.",
    }


@app.get("/v1/tools")
def list_tools():
    catalog = public_tool_catalog()
    enabled = sum(1 for item in catalog.values() if item["workflow_enabled"])
    dispatch_configured = bool(os.getenv("GITHUB_TOKEN") and os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY"))
    return {
        "tools": catalog,
        "integrations_catalogued": len(catalog),
        "workflow_enabled": enabled,
        "api_dispatch_enabled": dispatch_configured,
        "execution_enabled": dispatch_configured,
        "dispatch_modes": (["static", "reverse_engineering"] if dispatch_configured else []),
        "note": "API dispatch is restricted to approved static source scans. Active network testing and APK reverse engineering require separate workflows and scope checks.",
    }


@app.post("/v1/assets/register")
def register_source_asset(registration: SourceAssetRegistration, user: dict[str, Any] = Depends(current_user)):
    if registration.authorization_confirmed is not True:
        raise HTTPException(status_code=403, detail="Explicit authorization confirmation is required.")
    url, _, service_key = _config()
    headers = _service_headers(service_key)
    try:
        workspaces_response = httpx.get(
            f"{url}/rest/v1/workspaces",
            params={"owner_id": f"eq.{user['id']}", "select": "id", "limit": "1"},
            headers=headers,
            timeout=10.0,
        )
        workspaces_response.raise_for_status()
        workspaces = workspaces_response.json()
        if workspaces:
            workspace_id = workspaces[0]["id"]
        else:
            created = httpx.post(
                f"{url}/rest/v1/workspaces",
                json={"owner_id": user["id"], "name": registration.workspace_name},
                headers=_service_headers(service_key, "return=representation"),
                timeout=10.0,
            )
            created.raise_for_status()
            workspace_id = created.json()[0]["id"]

        asset_query = {
            "workspace_id": f"eq.{workspace_id}",
            "asset_type": "eq.source",
            "identifier": f"eq.{REPOSITORY}",
            "select": "id",
            "limit": "1",
        }
        existing_response = httpx.get(
            f"{url}/rest/v1/assets",
            params=asset_query,
            headers=headers,
            timeout=10.0,
        )
        existing_response.raise_for_status()
        existing = existing_response.json()
        payload = {
            "workspace_id": workspace_id,
            "created_by": user["id"],
            "asset_type": "source",
            "identifier": REPOSITORY,
            "authorization_confirmed": True,
            "authorization_note": registration.authorization_note,
            "allowed_tests": ["static"],
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        }
        if existing:
            asset_id = existing[0]["id"]
            updated = httpx.patch(
                f"{url}/rest/v1/assets",
                params={"id": f"eq.{asset_id}"},
                json={key: value for key, value in payload.items() if key not in {"workspace_id", "created_by", "asset_type", "identifier"}},
                headers=_service_headers(service_key, "return=representation"),
                timeout=10.0,
            )
            updated.raise_for_status()
        else:
            created_asset = httpx.post(
                f"{url}/rest/v1/assets",
                json=payload,
                headers=_service_headers(service_key, "return=representation"),
                timeout=10.0,
            )
            created_asset.raise_for_status()
            asset_id = created_asset.json()[0]["id"]
        return {
            "asset_id": asset_id,
            "workspace_id": workspace_id,
            "asset_type": "source",
            "identifier": REPOSITORY,
            "allowed_tests": ["static"],
            "expires_in_days": 30,
        }
    except HTTPException:
        raise
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Could not register the authorized source asset in Supabase.")


@app.post("/v1/apks/upload")
async def upload_apk(
    request: Request,
    file_name: str,
    authorization_note: str,
    authorization_confirmed: bool,
    user: dict[str, Any] = Depends(current_user),
):
    if authorization_confirmed is not True:
        raise HTTPException(status_code=403, detail="Explicit authorization confirmation is required for each APK upload.")
    if len(authorization_note.strip()) < 12:
        raise HTTPException(status_code=400, detail="A clear authorization statement is required.")
    safe_name = os.path.basename(file_name).replace(" ", "_")
    if not safe_name.lower().endswith(".apk") or len(safe_name) > 160:
        raise HTTPException(status_code=400, detail="Only APK files with a valid .apk filename are accepted.")
    content_length = int(request.headers.get("content-length", "0") or 0)
    if content_length > MAX_APK_BYTES:
        raise HTTPException(status_code=413, detail="APK exceeds the 150 MB upload limit.")
    data = await request.body()
    if not data or len(data) > MAX_APK_BYTES:
        raise HTTPException(status_code=413 if len(data) > MAX_APK_BYTES else 400, detail="APK is empty or exceeds the 150 MB upload limit.")
    if not data.startswith(APK_ZIP_SIGNATURE):
        raise HTTPException(status_code=415, detail="The uploaded file does not have a valid APK/ZIP signature.")
    url, _, service_key = _config()
    headers = _service_headers(service_key)
    workspace_response = httpx.get(
        f"{url}/rest/v1/workspaces",
        params={"owner_id":f"eq.{user['id']}","select":"id","limit":"1"},
        headers=headers, timeout=15.0
    )
    workspace_response.raise_for_status()
    workspaces = workspace_response.json()
    if workspaces:
        workspace_id = workspaces[0]["id"]
    else:
        created = httpx.post(f"{url}/rest/v1/workspaces",json={"owner_id":user["id"],"name":"Yasser Security Lab"},headers=_service_headers(service_key,"return=representation"),timeout=15.0)
        created.raise_for_status()
        workspace_id = created.json()[0]["id"]
    object_path = f"{user['id']}/{__import__('uuid').uuid4().hex}/{safe_name}"
    storage_headers = {"apikey":service_key,"Authorization":f"Bearer {service_key}","Content-Type":"application/vnd.android.package-archive","x-upsert":"false"}
    upload = httpx.post(f"{url}/storage/v1/object/{APK_BUCKET}/{object_path}",content=data,headers=storage_headers,timeout=90.0)
    if upload.status_code not in (200, 201):
        raise HTTPException(status_code=502,detail="Supabase Storage upload failed. Check that the private apk-uploads bucket exists.")
    asset_payload = {
        "workspace_id":workspace_id,"created_by":user["id"],"asset_type":"apk",
        "identifier":object_path,"authorization_confirmed":True,"authorization_note":authorization_note,
        "allowed_tests":["reverse_engineering"],"expires_at":(datetime.now(timezone.utc)+timedelta(days=7)).isoformat()
    }
    asset_response = httpx.post(f"{url}/rest/v1/assets",json=asset_payload,headers=_service_headers(service_key,"return=representation"),timeout=15.0)
    if asset_response.status_code not in (200,201):
        raise HTTPException(status_code=502,detail="APK uploaded, but its authorized asset record could not be created.")
    asset = asset_response.json()[0]
    signed = httpx.post(f"{url}/storage/v1/object/sign/{APK_BUCKET}/{object_path}",json={"expiresIn":7200},headers=_service_headers(service_key),timeout=15.0)
    if signed.status_code not in (200,201):
        raise HTTPException(status_code=502,detail="APK uploaded, but a temporary analysis download URL could not be created.")
    signed_path = signed.json().get("signedURL") or signed.json().get("signedUrl")
    if not signed_path:
        raise HTTPException(status_code=502,detail="Supabase did not return a signed APK download URL.")
    download_url = signed_path if signed_path.startswith("http") else f"{url}/storage/v1{signed_path}"
    job_payload = {
        "workspace_id":workspace_id,"asset_id":asset["id"],"requested_by":user["id"],
        "tool_key":"mobsf","mode":"reverse_engineering","status":"queued",
        "parameters":{"file_name":safe_name,"storage_path":object_path}
    }
    job_response = httpx.post(f"{url}/rest/v1/analysis_jobs",json=job_payload,headers=_service_headers(service_key,"return=representation"),timeout=15.0)
    job_response.raise_for_status()
    job = job_response.json()[0]
    try:
        _dispatch_apk(job["id"],download_url,safe_name)
    except HTTPException:
        httpx.patch(f"{url}/rest/v1/analysis_jobs",params={"id":f"eq.{job['id']}"},json={"status":"failed","finished_at":datetime.now(timezone.utc).isoformat()},headers=_service_headers(service_key,"return=minimal"),timeout=10.0)
        raise
    _audit(workspace_id,user["id"],job["id"],"apk_analysis_dispatched")
    return {"status":"queued","job_id":job["id"],"asset_id":asset["id"],"file_name":safe_name,"message":"APK uploaded and analysis workflow dispatched."}


SENSITIVE_TEXT_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.I | re.S), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b"), "[REDACTED_PAYMENT_SECRET]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{16,}"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)(?<![A-Za-z0-9])(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|secret)\s*([:=])\s*[\"']?[A-Za-z0-9._~+/=-]{8,}[\"']?"), r"\1\2[REDACTED]"),
]


def redact_sensitive_text(value: str) -> tuple[str, bool]:
    redacted = value
    for pattern, replacement in SENSITIVE_TEXT_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted, redacted != value


@app.post("/v1/assistant/review")
def assistant_review(request: AssistantRequest, user: dict[str, Any] = Depends(current_user)):
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="AI advisory is not configured. Add OPENROUTER_API_KEY to the Render service.")
    primary = os.getenv("OPENROUTER_MODEL", "cohere/north-mini-code:free")
    fallback = os.getenv("OPENROUTER_FALLBACK_MODEL", "nvidia/nemotron-3.5-lightning:free")
    safe_question, question_redacted = redact_sensitive_text(request.question)
    safe_context, context_redacted = redact_sensitive_text(request.context)
    messages = [
        {
            "role": "system",
            "content": (
                "You are a defensive cybersecurity advisor for an authorized security lab. "
                "Analyze only the supplied question and context. Do not execute tools, initiate scans, "
                "change targets, or claim that actions were performed. Require explicit authorization "
                "for any active testing. Prefer practical remediation, concise Arabic when the user writes "
                "Arabic, and clearly distinguish evidence from assumptions."
            ),
        },
        {
            "role": "user",
            "content": "Question:\n" + safe_question + "\n\nContext:\n" + safe_context,
        },
    ]
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://yasser-security-lab.vercel.app",
        "X-Title": "Yasser Security Lab",
    }
    failures: list[int] = []
    for model in dict.fromkeys([primary, fallback]):
        try:
            response = httpx.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json={"model": model, "messages": messages, "temperature": 0.2, "max_tokens": 1200},
                timeout=45.0,
            )
            if response.status_code != 200:
                failures.append(response.status_code)
                continue
            data = response.json()
            answer = data["choices"][0]["message"]["content"]
            if not isinstance(answer, str) or not answer.strip():
                failures.append(502)
                continue
            return {
                "answer": answer,
                "provider": "OpenRouter",
                "model": data.get("model") or model,
                "fallback_used": model != primary,
                "execution_enabled": False,
                "sensitive_content_redacted": question_redacted or context_redacted,
            }
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError):
            failures.append(502)
    raise HTTPException(
        status_code=502,
        detail="Both configured free AI models are temporarily unavailable. Retry later.",
    )


@app.post("/v1/jobs/plan")
def plan_job(job: JobPlan, user: dict[str, Any] = Depends(current_user)):
    if job.tool_key not in TOOLS:
        raise HTTPException(status_code=400, detail="Tool adapter is not enabled.")
    required_mode = TOOLS[job.tool_key]["mode"]
    if job.mode.value != required_mode:
        raise HTTPException(status_code=400, detail="Requested mode does not match this adapter.")
    asset = load_authorized_asset(job.asset_id, user["id"])
    _assert_asset_authorized(asset, job.mode)
    if job.mode == Mode.active:
        return {"status": "approval_required", "plan_only": True, "message": "Active assessment requires a separate server-recorded approval. No scan was started."}
    if not TOOLS[job.tool_key]["workflow_enabled"]:
        return {"status": "adapter_not_ready", "plan_only": True, "execution_enabled": False, "tool": job.tool_key}
    return {
        "status": "workflow_available",
        "plan_only": True,
        "execution_enabled": False,
        "tool": job.tool_key,
        "mode": job.mode.value,
        "asset": asset["identifier"],
        "message": "This endpoint only plans work. Use POST /v1/jobs/dispatch for approved static scans.",
    }


@app.post("/v1/jobs/dispatch")
def dispatch_job(job: JobPlan, user: dict[str, Any] = Depends(current_user)):
    if job.tool_key not in STATIC_TOOLS or job.mode != Mode.static:
        raise HTTPException(status_code=403, detail="The API currently dispatches static source-analysis tools only.")
    if job.tool_key not in TOOLS or TOOLS[job.tool_key]["mode"] != "static":
        raise HTTPException(status_code=400, detail="Tool and mode do not match.")
    if job.user_approved is not True:
        raise HTTPException(status_code=403, detail="Explicit per-job approval is required before dispatch.")
    asset = load_authorized_asset(job.asset_id, user["id"])
    _assert_asset_authorized(asset, job.mode)
    if asset.get("asset_type") != "source":
        raise HTTPException(status_code=400, detail="Static repository scans require a source asset registered in this workspace.")
    if not os.getenv("GITHUB_TOKEN"):
        raise HTTPException(status_code=503, detail="GitHub Actions dispatch is not configured on the API service.")
    record = _insert_job(job, asset, user["id"])
    try:
        _dispatch_static(record["id"])
    except HTTPException:
        url, _, service_key = _config()
        try:
            httpx.patch(
                f"{url}/rest/v1/analysis_jobs",
                params={"id": f"eq.{record['id']}"},
                json={"status": "failed", "finished_at": datetime.now(timezone.utc).isoformat()},
                headers=_service_headers(service_key, "return=minimal"),
                timeout=10.0,
            )
        except httpx.HTTPError:
            pass
        raise
    _audit(asset["workspace_id"], user["id"], record["id"], "analysis_job_dispatched")
    return {"status": "queued", "job_id": record["id"], "tool": job.tool_key, "mode": "static", "message": "GitHub Actions workflow accepted the dispatch. Query the job endpoint for progress."}


@app.get("/v1/jobs/{job_id}")
def job_status(job_id: str, user: dict[str, Any] = Depends(current_user)):
    job = _get_job(job_id, user["id"])
    run = _find_github_run(job_id, job["mode"]) if job["mode"] in {"static", "reverse_engineering"} else None
    return _sync_job_status(job, run)


# Persistent, approval-gated agent tasks for authorized static analysis.
class AgentTaskProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str = Field(min_length=8, max_length=80)
    action: str = Field(pattern="^full-static-suite$")
    objective: str = Field(min_length=8, max_length=1000)


@app.post("/v1/agent/tasks")
def propose_agent_task(proposal: AgentTaskProposal, user: dict[str, Any] = Depends(current_user)):
    asset = load_authorized_asset(proposal.asset_id, user["id"])
    _assert_asset_authorized(asset, Mode.static)
    if asset.get("asset_type") != "source":
        raise HTTPException(status_code=400, detail="Only authorized source-repository assets are accepted.")
    url, _, service_key = _config()
    payload = {
        "workspace_id": asset["workspace_id"],
        "asset_id": asset["id"],
        "requested_by": user["id"],
        "action": proposal.action,
        "objective": proposal.objective.strip(),
        "status": "proposed",
    }
    try:
        response = httpx.post(
            f"{url}/rest/v1/agent_tasks",
            json=payload,
            headers=_service_headers(service_key, "return=representation"),
            timeout=15.0,
        )
        response.raise_for_status()
        rows = response.json()
        if not rows:
            raise HTTPException(status_code=503, detail="The agent proposal was not saved.")
        _audit(asset["workspace_id"], user["id"], rows[0]["id"], "agent_task_proposed")
        return {
            "task": rows[0],
            "execution_started": False,
            "approval_required": True,
            "message": "Proposal saved. No workflow starts until you explicitly approve it.",
        }
    except HTTPException:
        raise
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Could not save the agent proposal.")


@app.post("/v1/agent/tasks/{task_id}/approve")
def approve_agent_task(task_id: str, user: dict[str, Any] = Depends(current_user)):
    url, _, service_key = _config()
    try:
        response = httpx.get(
            f"{url}/rest/v1/agent_tasks",
            params={
                "id": f"eq.{task_id}",
                "requested_by": f"eq.{user['id']}",
                "select": "id,workspace_id,asset_id,action,objective,status",
                "limit": "1",
            },
            headers=_service_headers(service_key),
            timeout=10.0,
        )
        response.raise_for_status()
        rows = response.json()
        if not rows:
            raise HTTPException(status_code=404, detail="Agent task was not found.")
        task = rows[0]
        if task["status"] != "proposed":
            raise HTTPException(status_code=409, detail="This task is no longer awaiting approval.")
        if task["action"] != "full-static-suite":
            raise HTTPException(status_code=403, detail="This action is not in the execution allowlist.")
        asset = load_authorized_asset(task["asset_id"], user["id"])
        _assert_asset_authorized(asset, Mode.static)
        if asset.get("asset_type") != "source":
            raise HTTPException(status_code=400, detail="The task no longer points to a source asset.")
        claim = httpx.patch(
            f"{url}/rest/v1/agent_tasks",
            params={"id": f"eq.{task_id}", "requested_by": f"eq.{user['id']}", "status": "eq.proposed"},
            json={
                "status": "approved",
                "approved_by": user["id"],
                "approved_at": datetime.now(timezone.utc).isoformat(),
            },
            headers=_service_headers(service_key, "return=representation"),
            timeout=10.0,
        )
        claim.raise_for_status()
        if not claim.json():
            raise HTTPException(status_code=409, detail="The task was already approved or changed.")
        job = JobPlan(
            asset_id=task["asset_id"],
            tool_key="full-static-suite",
            mode=Mode.static,
            user_approved=True,
            parameters={"agent_task_id": task_id, "objective": task["objective"]},
        )
        record = _insert_job(job, asset, user["id"])
        try:
            _dispatch_static(record["id"])
        except HTTPException:
            httpx.patch(
                f"{url}/rest/v1/agent_tasks",
                params={"id": f"eq.{task_id}"},
                json={"status": "failed"},
                headers=_service_headers(service_key, "return=minimal"),
                timeout=10.0,
            )
            raise
        httpx.patch(
            f"{url}/rest/v1/agent_tasks",
            params={"id": f"eq.{task_id}"},
            json={"status": "queued", "analysis_job_id": record["id"]},
            headers=_service_headers(service_key, "return=minimal"),
            timeout=10.0,
        ).raise_for_status()
        _audit(task["workspace_id"], user["id"], task_id, "agent_task_approved_and_dispatched")
        return {"task_id": task_id, "job_id": record["id"], "status": "queued", "execution_started": True}
    except HTTPException:
        raise
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="Could not approve or dispatch this agent task.")


# Server-to-server Replica MCP bridge. The MCP bearer token is never sent to Android.
REPLICA_TOOL_ALLOWLIST = {
    "replica_server_info",
    "replica_list_skills",
    "replica_get_skill",
    "replica_list_utilities",
    "workspace_list",
    "workspace_read",
    "workspace_mkdir",
    "workspace_write",
    "workspace_stat",
    "workspace_run",
    "replica_run_utility",
}
SAFE_REPLICA_COMMANDS = {
    ("git", "status", "--short"),
    ("git", "diff", "--stat"),
    ("git", "diff"),
    ("git", "log", "-5", "--oneline"),
    ("git", "ls-files"),
    ("pytest", "-q"),
    ("python3", "-m", "pytest", "-q"),
    ("npm", "test"),
    ("npm", "run", "build"),
    ("npm", "run", "lint"),
    ("npm", "run", "typecheck"),
}


class ReplicaToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    user_approved: bool = False


def _replica_config() -> tuple[str, str]:
    endpoint = os.getenv("REPLICA_MCP_URL", "https://replica-mcp-server-dfj0.onrender.com/mcp").strip()
    token = os.getenv("REPLICA_MCP_BEARER_TOKEN", "")
    if not endpoint.startswith("https://") or not token:
        raise HTTPException(status_code=503, detail="Replica MCP server configuration is incomplete.")
    return endpoint, token


async def _replica_list_tools_async() -> list[dict[str, Any]]:
    endpoint, token = _replica_config()
    async with streamablehttp_client(
        endpoint,
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
        sse_read_timeout=60,
    ) as (read_stream, write_stream, _get_session_id):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.list_tools()
            return [
                {
                    "name": tool.name,
                    "description": tool.description or "",
                    "input_schema": getattr(tool, "inputSchema", {}),
                }
                for tool in result.tools
                if tool.name in REPLICA_TOOL_ALLOWLIST
            ]


async def _replica_call_tool_async(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    endpoint, token = _replica_config()
    async with streamablehttp_client(
        endpoint,
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
        sse_read_timeout=120,
    ) as (read_stream, write_stream, _get_session_id):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, arguments=arguments)
            return {
                "is_error": bool(getattr(result, "isError", False)),
                "content": [
                    item.model_dump(mode="json", by_alias=True)
                    if hasattr(item, "model_dump") else {"text": str(item)}
                    for item in result.content
                ],
                "structured_content": getattr(result, "structuredContent", None),
            }


def _replica_list_tools() -> list[dict[str, Any]]:
    try:
        return asyncio.run(_replica_list_tools_async())
    except HTTPException:
        raise
    except Exception:
        logging.getLogger(__name__).exception("Replica MCP tool discovery failed")
        raise HTTPException(status_code=502, detail="Replica MCP server could not be reached.")


def _replica_call_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        return asyncio.run(_replica_call_tool_async(tool_name, arguments))
    except HTTPException:
        raise
    except Exception:
        logging.getLogger(__name__).exception("Replica MCP tool call failed: %s", tool_name)
        raise HTTPException(status_code=502, detail="Replica MCP tool call failed.")


@app.get("/v1/replica/tools")
def replica_tools(user: dict[str, Any] = Depends(current_user)):
    return {"tools": _replica_list_tools(), "approval_required_for_every_call": True}


@app.post("/v1/replica/call")
def replica_call(request: ReplicaToolCall, user: dict[str, Any] = Depends(current_user)):
    if request.user_approved is not True:
        raise HTTPException(status_code=403, detail="Explicit per-call approval is required.")
    if request.tool_name not in REPLICA_TOOL_ALLOWLIST:
        raise HTTPException(status_code=403, detail="This Replica MCP tool is not allowlisted.")
    if request.tool_name == "workspace_run":
        command = request.arguments.get("command")
        if not isinstance(command, list) or tuple(str(part) for part in command) not in SAFE_REPLICA_COMMANDS:
            raise HTTPException(status_code=403, detail="This project command is not in the safe command allowlist.")
    if request.tool_name == "workspace_write":
        content = request.arguments.get("content")
        if not isinstance(content, str) or len(content) > 200000:
            raise HTTPException(status_code=400, detail="Workspace writes are limited to 200 KB of text.")
    result = _replica_call_tool(request.tool_name, request.arguments)
    try:
        url, _, service_key = _config()
        audit_response = httpx.post(
            f"{url}/rest/v1/audit_events",
            json={
                "workspace_id": None,
                "actor_id": user["id"],
                "event_type": "replica_tool_called",
                "object_id": None,
                "details": {"tool_name": request.tool_name, "user_approved": True},
            },
            headers=_service_headers(service_key, "return=minimal"),
            timeout=10.0,
        )
        audit_response.raise_for_status()
    except httpx.HTTPError:
        logging.getLogger(__name__).warning("Replica MCP audit write failed.")
    return {"tool_name": request.tool_name, "result": result, "approval_recorded": True}
