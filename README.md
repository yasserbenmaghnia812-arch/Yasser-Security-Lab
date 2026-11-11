# Yasser Security Lab

Arabic-first Android security workbench built with Kotlin, Jetpack Compose, FastAPI, Supabase, and GitHub Actions.

## Implemented

- Authenticated Android app with Arabic RTL UI, Supabase sign-in, APK upload, and job status polling.
- Private APK storage and isolated GitHub Actions analysis using Apktool, JADX, and MobSF.
- Approved static source analysis with Semgrep, Gitleaks, Trivy, Checkov, Syft, Grype, YARA, and ClamAV.
- FastAPI service with Supabase ownership checks, scope validation, audit events, and advisory AI.
- Persistent approval-gated agent proposals for the fixed static-analysis workflow.
- Bounded agent tasks for API tests and Android Debug APK builds. Every execution requires explicit per-task approval.
- Replica MCP connection through the authenticated API. The remote MCP token stays in Render; the Android client never receives it. Every MCP tool call requires a separate approval.
- Optional on-device local coding model through llama.cpp in Termux. The APK does not bundle model weights.

## Local AI on Android

Run the setup script from the repository in Termux:

    bash scripts/setup-local-ai-termux.sh

It builds llama.cpp and downloads the Qwen2.5-Coder 0.5B Q4_0 GGUF model. Start the local server using the command printed by the script. In the app, use:

- URL: `http://127.0.0.1:11434/v1`
- Model: `yasser-coder-0.5b`

This is a small local assistant suitable as a starting point for a 4 GB RAM device. Build time and inference speed depend on available memory, heat, and CPU load.

## Replica MCP

The app calls `GET /v1/replica/tools` and `POST /v1/replica/call` through the FastAPI service. The API connects to the existing Streamable HTTP server at `https://replica-mcp-server-dfj0.onrender.com/mcp` using a server-only bearer token. The MCP server now rejects unauthenticated calls.

The API exposes an allowlist of Replica tools. `workspace_run` accepts only exact safe command forms; arbitrary shell commands are rejected. All tool calls require explicit approval from the signed-in user.

## Approval-gated API

- `POST /v1/agent/plan`: preview API-test or Android Debug APK task.
- `POST /v1/agent/execute`: run one allowlisted task only with `user_approved=true`.
- `POST /v1/agent/tasks`: save a static-analysis task proposal; does not execute.
- `POST /v1/agent/tasks/{task_id}/approve`: recheck asset ownership and authorization, then dispatch the approved static scan.

## Build and test

- Android Debug APK: GitHub Actions → Android Debug APK → latest successful run → Artifacts.
- API tests: `cd api && pip install -r requirements.txt && pytest -q`.
- APK analysis: upload only APKs you own or are authorized to assess, with explicit confirmation.

## Safety

No arbitrary shell endpoint, exploit runner, stealth behavior, or autonomous source edits are exposed. Replica workspace writes and commands require explicit approval and remain constrained to the MCP server's isolated workspace. Keep Supabase service-role, GitHub, and Replica MCP tokens on the server only.
