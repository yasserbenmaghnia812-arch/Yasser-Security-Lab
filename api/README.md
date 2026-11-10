# Yasser Security Lab API

Python 3.11+:

    pip install -r requirements.txt
    uvicorn main:app --reload

## Endpoints

- `GET /health` — service health.
- `GET /v1/tools` — 27-tool registry and current dispatch configuration.
- `POST /v1/jobs/plan` — authenticated scope validation; never starts a scan.
- `POST /v1/jobs/dispatch` — dispatches an approved **static source-analysis** job to GitHub Actions.
- `GET /v1/jobs/{job_id}` — returns job state and the matching GitHub Actions run when available.

All job endpoints require a valid Supabase access token in the Bearer header. The API checks asset ownership, server-recorded authorization, allowed test mode, and expiry before dispatch.

## Actual dispatch coverage

The API dispatch path is currently restricted to these 8 static tools: Semgrep, Gitleaks, Trivy, Checkov, Syft, Grype, YARA, and ClamAV. It creates an `analysis_jobs` row, dispatches `.github/workflows/security-static.yml` with a correlation ID, writes an audit event, and resolves the GitHub run from its run name when the client polls the job endpoint.

Active network tests are **not** dispatched by this API. They remain behind the separate manual workflow, a single exact public target, an authorization checkbox, and a scope note. The API does not dispatch APK reverse-engineering jobs yet: private APK upload and secure transfer to an isolated runner must be completed first.

## Required Render environment variables

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY` (publishable/anon key only)
- `SUPABASE_SERVICE_ROLE_KEY` (server-side secret; never ship to Android or Vercel browser code)
- `GITHUB_TOKEN` (fine-grained token with Actions: write for this repository; never ship to the APK)
- `GITHUB_REPOSITORY` (defaults to this repository)
- `ALLOWED_ORIGINS` (comma-separated exact web origins; can remain empty for native-only clients)

Do not send secrets in chat or commit them to Git. Add them through Render's Environment page. The GitHub token should be least-privilege and stored only on the server.

## Current tool execution model

- 8 source-analysis tools run in `.github/workflows/security-static.yml`.
- 7 APK/native-binary analyzers run in that workflow only when an authorized APK exists under `authorized-samples/`.
- 11 low-impact network tools run in `.github/workflows/security-network-approved.yml` only after manual authorization confirmation and exact target/scope validation.
- mitmproxy is a local Termux setup documented in `docs/MITMPROXY-TERMUX.md`.

No scanner accepts arbitrary shell input. Active network workflow excludes exploit, intrusive, and denial-of-service templates and uses bounded request rates.
