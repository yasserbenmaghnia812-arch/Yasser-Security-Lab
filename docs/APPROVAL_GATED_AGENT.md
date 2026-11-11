# Approval-gated agent API

The API exposes a deliberately narrow first execution path:

1. Authenticate with a Supabase access token.
2. Register/verify a source asset with the existing authorization workflow.
3. Create a proposal with `POST /v1/agent/tasks` using `asset_id`, `action: "full-static-suite"`, and an objective.
4. Review the returned proposal. This endpoint never starts a workflow.
5. Explicitly approve with `POST /v1/agent/tasks/{task_id}/approve`.
6. The API rechecks asset ownership, authorization expiry, and static scope, records the approver, creates an analysis job, then dispatches the existing static GitHub Actions workflow.

## Limits

- Only the allowlisted `full-static-suite` action is executable.
- Active network scans, arbitrary shell commands, repository writes, file deletion, and APK modification are not exposed to the agent.
- The approval endpoint is single-use: only tasks still in `proposed` state can be claimed.
- Apply migration `202611110001_agent_tasks.sql` before using these endpoints.
- Configure Render secrets already documented in `render.yaml`; never commit service-role or GitHub tokens.
- This is an approval-gated task dispatcher, not an autonomous code-editing agent. Repository patch generation and Replica MCP tool execution remain separate integrations.
