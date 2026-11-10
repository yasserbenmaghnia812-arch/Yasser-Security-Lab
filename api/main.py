from enum import Enum
from typing import Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, ConfigDict

app = FastAPI(title="Yasser Security Lab API", version="0.1.0")

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
    authorization_confirmed: bool = False
    approved: bool = False

# Public API keys map to reviewed adapters. This is a registry, not an executable shell.
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

@app.get("/health")
def health():
    return {"status": "ok", "service": "yasser-security-lab-api"}

@app.get("/v1/tools")
def list_tools():
    return {"tools": TOOLS, "integrations_catalogued": 27}

@app.post("/v1/jobs/plan")
def plan_job(job: JobPlan):
    if job.tool_key not in TOOLS:
        raise HTTPException(status_code=400, detail="Tool adapter is not enabled.")
    required_mode = TOOLS[job.tool_key]["mode"]
    if job.mode.value != required_mode:
        raise HTTPException(status_code=400, detail="Requested mode does not match this adapter.")
    if not job.authorization_confirmed:
        raise HTTPException(status_code=403, detail="Confirm ownership or written authorization first.")
    if job.mode == Mode.active and not job.approved:
        return {"status": "approval_required", "plan_only": True,
                "message": "Active assessment requires explicit approval before execution."}
    # Execution is intentionally not implemented in this bootstrap API.
    return {"status": "planned", "plan_only": True,
            "message": "Adapter execution is not enabled in this scaffold.",
            "tool": job.tool_key, "mode": job.mode.value}
