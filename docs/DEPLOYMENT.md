# Deployment guide

## Existing services

- Supabase project: `Yasser-Security-Lab`, reference `jokemrlulcvoiahfnagz`.
- Render API: `yasser-security-lab-api-7w2p`, region Frankfurt, free plan, root directory `api`.
- Render Replica MCP: `replica-mcp-server-dfj0`, region Frankfurt, free plan, repository `rea-ai`, root directory `replica-mcp`.
- The Android client calls the FastAPI service. It does not hold the Replica MCP server token.

## Supabase

The core tables are `workspaces`, `assets`, `analysis_jobs`, `findings`, and `audit_events`. All have RLS enabled.

The approval-gated task migration creates `public.agent_tasks`, enables RLS, grants authenticated users read access to their own rows, and keeps writes server-only through the service role. It has been applied to the selected project and verified.

Never place the Supabase service-role key in Android, browser code, GitHub, or chat.

## Render API environment

The existing API service uses the following server-only variables:

| Variable | Purpose |
|---|---|
| `SUPABASE_URL` | Supabase project URL |
| `SUPABASE_ANON_KEY` | Publishable/anon key used for Auth validation |
| `SUPABASE_SERVICE_ROLE_KEY` | Server-only Postgres and private Storage operations |
| `GITHUB_TOKEN` | Fine-grained token with Actions read/write for this repository |
| `GITHUB_REPOSITORY` | `yasserbenmaghnia812-arch/Yasser-Security-Lab` |
| `REPLICA_MCP_URL` | `https://replica-mcp-server-dfj0.onrender.com/mcp` |
| `REPLICA_MCP_BEARER_TOKEN` | Server-to-server credential matching the Replica MCP service |
| `OPENROUTER_API_KEY` | Optional server-side advisory model key |
| `ALLOWED_ORIGINS` | Optional exact browser origins |

Do not replace the existing environment wholesale; merge only the new Replica MCP variables. Never print or commit token values.

## Render Replica MCP environment

The Replica MCP service requires `MCP_BEARER_TOKEN`. Every `/mcp` request must present the matching Authorization Bearer header. Health remains public and does not disclose the token. The MCP server's workspace is temporary on the free plan and may be lost after restart or redeploy.

## API endpoints

- `GET /health` — service health.
- `GET /v1/config` — public Supabase URL and publishable key only.
- `GET /v1/replica/tools` — authenticated allowlisted tool discovery.
- `POST /v1/replica/call` — authenticated MCP tool call; requires `user_approved=true`.
- `POST /v1/agent/plan` — preview an allowlisted task.
- `POST /v1/agent/execute` — dispatch API tests or Debug APK build only after explicit approval.
- `POST /v1/agent/tasks` — create a persistent static-analysis proposal without executing it.
- `POST /v1/agent/tasks/{task_id}/approve` — revalidate scope and dispatch after explicit approval.
- `POST /v1/apks/upload` — private authorized APK upload and analysis dispatch.
- `GET /v1/jobs/{job_id}` — job status.

## Android local model

Run `scripts/setup-local-ai-termux.sh` in Termux. It builds llama.cpp with two jobs and downloads the Qwen2.5-Coder 0.5B Q4_0 model. Start the server on `127.0.0.1:11434`. The app uses `http://127.0.0.1:11434/v1` and model ID `yasser-coder-0.5b`. The model is not embedded in the APK.

## Validation

1. Check Render API `/health` and `/v1/config`.
2. Check Replica MCP `/health`; an unauthenticated POST to `/mcp` must be rejected.
3. Sign in from Android and discover Replica MCP tools.
4. Confirm each MCP call is blocked until its approval checkbox is selected.
5. Confirm API-test and Debug APK agent tasks show a preview before approval.
6. Run the API test workflow and Android Debug APK workflow.
7. Test llama.cpp locally in Termux on the target device.

Free Render instances may sleep. Free-tier workspaces are not guaranteed to be always-on or persistent. The local model requires the Termux server to be running while the app uses it.
