# Deployment plan

## Services
- GitHub: source and Actions.
- Supabase: Auth, Postgres, private Storage.
- Render: API and isolated worker. Free instances can sleep and are not suitable for sustained CPU-heavy reverse engineering.
- Vercel: optional browser console; Android can call the API directly.

## Environment variable names
API: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY (server only), JWT_AUDIENCE, ALLOWED_ORIGINS.

AI optional: QWEN_OPENAI_COMPATIBLE_BASE_URL, QWEN_MODEL, QWEN_API_KEY, DEEPSEEK_OPENAI_COMPATIBLE_BASE_URL, DEEPSEEK_MODEL, DEEPSEEK_API_KEY.

Worker: JOB_SIGNING_SECRET, ARTIFACT_BUCKET, MAX_JOB_SECONDS, MAX_UPLOAD_MB.

## Provisioning order
1. Review/apply Supabase migration; verify RLS and private Storage policies.
2. Deploy API and worker to Render with isolated execution.
3. Configure Vercel only if a browser console is required.
4. Add GitHub Actions secrets after reviewing workflow permissions.
5. Build/test the Android APK on a physical device.

Free tiers do not guarantee always-on compute, large APK analysis, GPU inference, or high-volume scanning. Start with static analysis and short queued jobs.
