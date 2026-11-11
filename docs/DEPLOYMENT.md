# Deployment guide

## Components and current responsibilities

- **GitHub Actions:** Android Debug APK build, API unit tests, static source scanning, and authorized APK analysis.
- **Supabase:** Auth, Postgres metadata, row-level security, and the private `apk-uploads` Storage bucket.
- **Render:** one FastAPI web service. The repository does not currently deploy a separate worker service.
- **Vercel:** optional browser console. The Android client calls the API directly.

CPU-heavy decompilation and static APK analysis run in ephemeral GitHub Actions runners, not inside the small Render web service. Free Render instances can sleep between requests; a first request may be delayed.

## Supabase

Project reference: `jokemrlulcvoiahfnagz` (Yasser Security Lab).

The current project has the core tables with RLS enabled and a private `apk-uploads` bucket. Do not create a second project or rerun the initial schema migration without checking its current state.

Required tables: `workspaces`, `assets`, `analysis_jobs`, `findings`, `audit_events`.

The API uses the service-role key only from its server environment. Never place it in the Android app, browser bundle, GitHub repository, or chat.

## Render API service

The root-level `render.yaml` defines a free Python web service:

- Root directory: `api`
- Build: `pip install -r requirements.txt`
- Start: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health check: `/health`

Configure these values in the Render service Environment page:

| Variable | Required | Purpose |
|---|---|---|
| `SUPABASE_URL` | Yes | Supabase project URL |
| `SUPABASE_ANON_KEY` | Yes | Supabase publishable/anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes | Server-only database and private Storage operations |
| `GITHUB_TOKEN` | Yes | Fine-grained GitHub token, Actions read/write for this repository |
| `GITHUB_REPOSITORY` | Yes | `yasserbenmaghnia812-arch/Yasser-Security-Lab` |
| `ALLOWED_ORIGINS` | Optional | Exact browser origins; may be empty for native-only clients |
| `OPENROUTER_API_KEY` | Optional | Enables cloud advisory AI; it is not required for APK builds or static analysis |
| `OPENROUTER_MODEL` | Optional | Defaults to `cohere/north-mini-code:free` |
| `OPENROUTER_FALLBACK_MODEL` | Optional | Defaults to `nvidia/nemotron-3.5-lightning:free` |

The fine-grained GitHub token should be limited to this repository. Grant only the repository permissions needed to dispatch workflows and read their run status. Do not use a personal token with broad account permissions.

The two default OpenRouter model routes are currently listed as free, but free routes are rate-limited and their availability can change. Requests to the provider leave your server. The API redacts several common secret formats before forwarding advisory prompts, but this is best-effort pattern matching, not a guarantee; do not submit credentials, private keys, personal data, or confidential source code to external free model endpoints.

## GitHub Actions

Ensure repository Actions are enabled. The API dispatch token needs Actions write permission and permission to read run status. Workflow jobs use short-lived GitHub-hosted runners and upload scan reports as expiring artifacts.

Never add Supabase service-role keys, OpenRouter keys, or the Render API's GitHub token to an Android APK or a client-side environment.

## Android

The workflow `.github/workflows/android-apk.yml` builds a **Debug** APK. It is suitable for testing, not public production distribution. A production release requires a separately generated signing keystore and protected signing secrets. Do not share the keystore or passwords.

The application requires Android 10 (API 29) or newer. The loopback-only HTTP exception is used only for an optional local inference endpoint at `127.0.0.1` or `localhost`; external cleartext traffic remains disabled.

## Not yet provisioned or integrated

- Render deployment and secret values still need to be configured in the selected Render workspace.
- Replica MCP has no endpoint, transport, or credentials in this repository, so it is not connected.
- The local chat panel does not embed a model runtime; it needs a local OpenAI-compatible inference server.
- The advisory AI endpoint does not execute code, edit files, or start tools.
- Ghidra, Androguard, APKLeaks, and radare2 are not part of the verified API-triggered APK upload workflow.

## Validation checklist

1. Confirm Render `/health` returns `{"status":"ok"}`.
2. Confirm `/v1/config` returns the Supabase URL, publishable key, and expected `ai_enabled` boolean without revealing server secrets.
3. Sign in from the Android app and confirm the app obtains a valid Supabase session.
4. Register the fixed source repository; confirm explicit approval is required for every static scan.
5. Upload only an owned or explicitly authorized APK and confirm the upload checkbox is required each time.
6. Verify GitHub Actions run status and download the Apktool/JADX/MobSF report artifact.
7. Install the Debug APK on a physical Android 10+ device and test sign-in, local inference connection, AI advisory (when enabled), static scan dispatch, APK upload, and job polling.

## Free-tier limitations

Free cloud instances may sleep and may impose CPU, memory, execution-time, or storage quotas. They are not guaranteed to be always-on and are not a substitute for persistent workers or GPU inference. The Android local chat panel does not include a bundled model; on-device inference requires a compatible local inference server and sufficient device memory.
