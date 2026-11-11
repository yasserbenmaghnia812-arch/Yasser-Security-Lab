# Yasser Security Lab API

Python 3.11+:

    pip install -r requirements.txt
    uvicorn main:app --reload

## Endpoints

- `GET /health` — service health.
- `GET /v1/config` — public Supabase URL and publishable key only; never returns the service-role key.
- `POST /v1/assets/register` — registers the fixed source repository after explicit ownership/authorization attestation.
- `GET /v1/tools` — 27-tool registry and current dispatch configuration.
- `POST /v1/assistant/review` — authenticated defensive AI advice; never executes tools.
- `POST /v1/jobs/plan` — authenticated scope validation; never starts a scan.
- `POST /v1/jobs/dispatch` — dispatches an approved **static source-analysis** job to GitHub Actions.
- `GET /v1/jobs/{job_id}` — returns job state and the matching GitHub Actions run when available.
- `POST /v1/apks/upload` — authenticated private APK upload and GitHub Actions reverse-engineering dispatch. Requires `file_name`, `authorization_note`, and explicit `authorization_confirmed=true` on every upload.

All job endpoints require a valid Supabase access token in the Bearer header. The API checks asset ownership, server-recorded authorization, allowed test mode, and expiry before dispatch. Static scan dispatch additionally requires `user_approved=true` on every request and records `approved_at`/`approved_by` in the job row. APK upload separately requires `authorization_confirmed=true` for every uploaded file.

## Actual dispatch coverage

The static-source dispatch path supports 8 verified source-analysis tools: Semgrep, Gitleaks, Trivy, Checkov, Syft, Grype, YARA, and ClamAV. It creates an `analysis_jobs` row, dispatches `.github/workflows/security-static.yml`, writes an audit event, and resolves the GitHub run when the client polls the job endpoint.

The separate `POST /v1/apks/upload` route accepts an owned or explicitly authorized APK, validates the ZIP signature and size, stores the file in the private `apk-uploads` bucket, creates a time-limited signed download URL, records a reverse-engineering job, and dispatches `.github/workflows/apk-analysis-api.yml`. Every upload requires both an authorization note and the explicit `authorization_confirmed=true` confirmation. The workflow runs Apktool, JADX, and MobSF; partial JADX results are recorded without silently treating them as a clean decompilation.

Active network assessments are **not** dispatched through the Android API. They remain behind the separate manual workflow, a single exact public target, an authorization checkbox, and a scope note. Ghidra, Androguard, APKLeaks, and radare2 are catalogued but are not part of the verified API-triggered APK workflow yet.

## Required Render environment variables

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY` (publishable/anon key only)
- `SUPABASE_SERVICE_ROLE_KEY` (server-side secret; never ship to Android or Vercel browser code)
- `GITHUB_TOKEN` (fine-grained token with Actions: read/write for this repository; never ship to the APK)
- `OPENROUTER_API_KEY` (optional; server-side key for free open-weight advisory models)
- `GITHUB_REPOSITORY` (defaults to this repository)
- `ALLOWED_ORIGINS` (comma-separated exact web origins; can remain empty for native-only clients)

Do not send secrets in chat or commit them to Git. Add them through Render's Environment page. The GitHub token should be least-privilege and stored only on the server.

## AI advisory model

The API supports OpenRouter's free open-weight model routes. Defaults are `cohere/north-mini-code:free` with `nvidia/nemotron-3.5-lightning:free` as fallback. Both are configurable with `OPENROUTER_MODEL` and `OPENROUTER_FALLBACK_MODEL`. These routes are currently listed at $0 but are rate-limited and can change. The advisory endpoint applies best-effort redaction to common PEM keys, AWS/GitHub/Stripe credentials, Bearer tokens, JWTs, and labelled key/password assignments before forwarding prompts. This is not a complete data-loss-prevention system: do not submit passwords, private keys, personal data, or confidential source code to an external model. The assistant is advisory-only and has no tool execution permissions.

## Current tool execution model

- 8 source-analysis tools run in `.github/workflows/security-static.yml`.
- The API-triggered APK workflow runs Apktool, JADX, and MobSF on a privately uploaded, user-authorized APK.
- 11 low-impact network tools run in `.github/workflows/security-network-approved.yml` only after manual authorization confirmation and exact target/scope validation.
- mitmproxy is a local Termux setup documented in `docs/MITMPROXY-TERMUX.md`.

No scanner accepts arbitrary shell input. Active network workflow excludes exploit, intrusive, and denial-of-service templates and uses bounded request rates.
