# Replica MCP and approval-gated agent

The Android app connects to the user's authenticated FastAPI session. The API connects server-to-server to the existing Replica MCP Streamable HTTP service. The MCP bearer token is stored only in Render environment variables and is never sent to Android.

## Replica MCP

- `GET /v1/replica/tools` discovers allowlisted tools for the authenticated user.
- `POST /v1/replica/call` calls one tool and requires `user_approved=true` on every invocation.
- The API allowlists Replica's documented workspace/skill tools.
- `workspace_run` is restricted to exact read/test/build command forms; arbitrary shell commands are rejected.
- Workspace paths are constrained by the Replica MCP server to its isolated workspace root.
- The remote MCP endpoint requires `Authorization: Bearer` and is configured with `REPLICA_MCP_URL` and `REPLICA_MCP_BEARER_TOKEN` on the API service.

## Local model on Android

Run `scripts/setup-local-ai-termux.sh` in Termux to build llama.cpp and download the Qwen2.5-Coder 0.5B Q4_0 model. Then start the local OpenAI-compatible server with the command printed by the script. In the Android app, use `http://127.0.0.1:11434/v1` and model id `yasser-coder-0.5b`. The model is not bundled into the APK. A 0.5B model is selected to reduce memory pressure on 4 GB devices; inference speed still depends on thermal and memory conditions.

## Approval-gated tasks

- `POST /v1/agent/plan` previews only the allowlisted API test or Android debug APK task.
- `POST /v1/agent/execute` requires an authenticated user and `user_approved=true`.
- `POST /v1/agent/tasks` stores a proposal for the authorized static analysis suite without executing it.
- `POST /v1/agent/tasks/{task_id}/approve` rechecks ownership and authorization before dispatching the static workflow.
- No arbitrary shell execution, exploit execution, or autonomous source edits are exposed.

Apply `supabase/migrations/202611110001_agent_tasks.sql` before using persistent static-analysis proposals.
