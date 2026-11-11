# Yasser Security Lab

Arabic-first, permission-first Android security workbench. The repository contains an Android client, a FastAPI service, Supabase schema, and GitHub Actions workflows for static source checks and authorized APK analysis.

> **Current verified status (2026-11-11):** the Android Debug APK builds successfully in GitHub Actions; the API unit tests pass; the Supabase project is active, its core tables have RLS enabled, and its private `apk-uploads` bucket is present. The self-test APK workflow completed Apktool, partial JADX decompilation, and MobSF static analysis; its report artifact is available from the linked Actions run. Cloud API availability and the APK upload-to-remote-analysis path still require a configured/deployed Render service and GitHub Actions credentials. No successful real-user APK upload has yet been verified.

## Included

- Android client: Kotlin, Jetpack Compose, Arabic RTL login and APK upload/status UI.
- Per-operation authorization: the user attests repository ownership, confirms each static scan separately, and confirms every APK upload. The API enforces per-scan and per-upload confirmation server-side.
- APK workflow: private Supabase Storage upload, short-lived signed URL, isolated GitHub Actions runner, Apktool/JADX decompilation and MobSF static scan.
- Static source workflow: one explicit full-suite action that runs all 8 source-analysis tools (Semgrep, Gitleaks, Trivy, Checkov, Syft, Grype, YARA, ClamAV).
- API: FastAPI with Supabase Auth, tenant-owned workspaces, server-side asset authorization, audit events, and an advisory-only OpenRouter endpoint.
- Local chat panel: loopback-only OpenAI-compatible inference endpoint. It does **not** bundle a model runtime, start a local inference server, or connect directly to LocalMind; a separate local server/bridge is required.

## Not yet integrated or verified

- Replica MCP: not connected. The repository does not contain a Replica endpoint, transport, or authentication configuration.
- Autonomous coding agent: not implemented. The AI review endpoint is advisory-only and cannot run tools or edit projects.
- Fully embedded offline LLM: not bundled. The local chat panel only connects to an already-running local inference server.
- Ghidra, Androguard, APKLeaks, and radare2: catalogued, but not part of the verified API-triggered APK pipeline.
- Active network tools: remain in separate approval-gated workflows; they are not dispatched from the Android API.
- Cloud deployment: Render service state and required server secrets have not been verified in this session.

## Architecture

- `app/`: Kotlin + Jetpack Compose client.
- `api/`: Python FastAPI orchestration and authentication.
- `worker/`: isolated typed-job runner scaffolding; it does not accept arbitrary shell commands.
- `supabase/migrations/`: Postgres schema and RLS policies.
- `.github/workflows/`: Android build, API tests, source scans, and APK analysis.
- `docs/`: tool catalogue, deployment notes, and security guidance.

## Build and test

- Debug APK: `.github/workflows/android-apk.yml` (ready for device testing; debug-signed and debuggable).
- Signed Release APK: `.github/workflows/android-release.yml` (non-debuggable; requires your own persistent release keystore in four protected GitHub Actions secrets: `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`). This release workflow has not yet been run because the private signing keystore is not configured.

Android Debug APK:

    GitHub → Actions → Android Debug APK → latest successful run → Artifacts

API tests:

    cd api
    pip install -r requirements.txt
    pytest -q

APK self-test:

    GitHub → Actions → Analyze the YSL debug APK

The APK self-test builds this project's own debug APK, runs Apktool and JADX, attempts a MobSF static scan, and uploads logs/reports as an artifact. JADX may report partial decompilation for obfuscated or unsupported bytecode; its exit code and extracted-source count are retained separately from Apktool and MobSF results.

## Security model

Only analyze files, apps, repositories, and targets you own or are explicitly authorized to assess. No stealth, persistence, credential theft, destructive payloads, unauthorized exploitation, or autonomous exploitation. Active/high-impact operations require separate approval and bounded scope.

Never commit secrets. Keep the Supabase service-role key, GitHub token, and any AI provider key on the server only. Read `api/README.md` and `docs/DEPLOYMENT.md` before deployment.
