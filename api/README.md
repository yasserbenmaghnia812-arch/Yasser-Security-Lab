# Yasser Security Lab API

Python 3.11+:

    pip install -r requirements.txt
    uvicorn main:app --reload

## Endpoints

- `GET /health` — service health.
- `GET /v1/tools` — 27-tool registry with honest workflow availability.
- `POST /v1/jobs/plan` — authenticated scope validation and plan only.

## Current execution model

- 8 source-analysis tools run in `.github/workflows/security-static.yml`.
- 7 APK/native-binary analyzers run in that workflow when an authorized APK exists under `authorized-samples/`.
- 11 low-impact network tools run in `.github/workflows/security-network-approved.yml` only after a manual authorization confirmation, a single exact public target, and a scope note.
- mitmproxy is a local Termux setup documented in `docs/MITMPROXY-TERMUX.md`.

The GitHub Actions workflows are real and separate from the API. The API currently verifies Supabase bearer tokens, checks workspace ownership and asset authorization, and plans jobs; it does **not** dispatch workflows or execute scanners. Do not describe the API as a connected job runner until GitHub dispatch credentials, a durable queue, result callbacks, and audit writes are configured.

## Required production work

- Configure `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` as Render secrets.
- Add a least-privilege GitHub App or fine-grained token for workflow dispatch; never place it in the APK.
- Implement signed upload/download URLs for private Supabase Storage.
- Implement job result callbacks and normalized finding persistence.
- Deploy an isolated worker with resource, timeout, egress, and output limits.
- Keep active tests behind server-recorded approvals and exact allowlisted scope.

No scanner accepts arbitrary shell input. Active network workflow excludes exploit, intrusive, and denial-of-service templates and uses bounded request rates.
