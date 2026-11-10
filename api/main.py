import logging
import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from tool_registry import TOOL_REGISTRY, public_tool_catalog

app = FastAPI(title="Yasser Security Lab API", version="0.3.0")
security = HTTPBearer(auto_error=False)
REPOSITORY = os.getenv("GITHUB_REPOSITORY", "yasserbenmaghnia812-arch/Yasser-Security-Lab")
STATIC_WORKFLOW = "security-static.yml"
APK_WORKFLOW = "apk-analysis-api.yml"
APK_BUCKET = "apk-uploads"
MAX_APK_BYTES = 150 * 1024 * 1024
STATIC_TOOLS = {"semgrep", "gitleaks", "trivy", "checkov", "grype", "syft", "yara", "clamav"}

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


class SourceAssetRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace_name: str = Field(default="Yasser Security Lab", min_length=1, max_length=100)
    authorization_confirmed: bool
    authorization_note: str = Field(min_length=12, max_length=2000)


class AssistantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(min_length=5, max_length=4000)
    context: str = Field(default="", max_length=5000)


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
        app.logger.warning("Audit write failed for job %s", job_id)


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
    user: dict[str, Any] = Depends(current_user),
):
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
    if not data.startswith(b"PK\\x03\\x04"):
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


@app.post("/v1/assistant/review")
def assistant_review(request: AssistantRequest, user: dict[str, Any] = Depends(current_user)):
    api_key = os.getenv("OPENROUTER_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="AI advisory is not configured. Add OPENROUTER_API_KEY to the Render service.")
    primary = os.getenv("OPENROUTER_MODEL", "cohere/north-mini-code:free")
    fallback = os.getenv("OPENROUTER_FALLBACK_MODEL", "nvidia/nemotron-3.5-lightning:free")
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
            "content": "Question:\n" + request.question + "\n\nContext:\n" + request.context,
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
