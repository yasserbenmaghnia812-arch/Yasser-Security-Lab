# Yasser Security Lab

Permission-first mobile security workbench: Android client, cloud API, isolated analysis jobs, and professional reports.

**Authorized-use boundary:** jobs run only against assets the signed-in user owns or is explicitly authorized to assess. No stealth, persistence, credential theft, destructive payloads, unauthorized exploitation, or autonomous exploitation. High-impact actions require explicit per-job approval.

## Product
- Arabic-first RTL Android app; charcoal, off-white, and restrained red palette.
- 27 open-source integrations listed in docs/TOOLS.md.
- Two advisory open-weight AI models: Qwen2.5-Coder-7B-Instruct (code/remediation) and DeepSeek-R1-Distill-Qwen-7B (reasoning/report review). Hosting/inference is not assumed free.
- APK static analysis, authorized dynamic testing, reverse engineering, and behavioral comparison ("replica analysis") for user-owned/authorized apps.
- Evidence-based Markdown/JSON/PDF reports.

## Architecture
- android/: Kotlin + Jetpack Compose client.
- api/: Python FastAPI orchestration.
- worker/: isolated typed-job runner; never executes arbitrary chat commands.
- supabase/migrations/: tenant-isolated schema and RLS.
- .github/workflows/: CI and Android APK build.
- docs/: tools, security, deployment.

This repository is being scaffolded. A commit does not mean cloud services are deployed or an APK has been built. Deployment needs owner-connected Render, Supabase, Vercel, and GitHub settings.

See docs/DEPLOYMENT.md. Never commit secrets.
