create extension if not exists pgcrypto;

create table if not exists public.workspaces (
 id uuid primary key default gen_random_uuid(),
 owner_id uuid not null references auth.users(id) on delete cascade,
 name text not null check (length(name) between 1 and 100),
 created_at timestamptz not null default now()
);
create table if not exists public.assets (
 id uuid primary key default gen_random_uuid(),
 workspace_id uuid not null references public.workspaces(id) on delete cascade,
 created_by uuid not null references auth.users(id) on delete cascade,
 asset_type text not null check (asset_type in ('domain','ip','cidr','apk','source','container')),
 identifier text not null,
 authorization_confirmed boolean not null default false,
 authorization_note text,
 allowed_tests text[] not null default array['passive']::text[],
 expires_at timestamptz,
 created_at timestamptz not null default now(),
 unique(workspace_id, asset_type, identifier)
);
create table if not exists public.analysis_jobs (
 id uuid primary key default gen_random_uuid(),
 workspace_id uuid not null references public.workspaces(id) on delete cascade,
 asset_id uuid not null references public.assets(id) on delete restrict,
 requested_by uuid not null references auth.users(id) on delete cascade,
 tool_key text not null check (length(tool_key) between 1 and 80),
 mode text not null check (mode in ('passive','active','static','reverse_engineering')),
 status text not null default 'queued' check (status in ('queued','running','succeeded','failed','cancelled')),
 approved_at timestamptz,
 approved_by uuid references auth.users(id),
 parameters jsonb not null default '{}'::jsonb,
 started_at timestamptz,
 finished_at timestamptz,
 created_at timestamptz not null default now()
);
create table if not exists public.findings (
 id uuid primary key default gen_random_uuid(),
 job_id uuid not null references public.analysis_jobs(id) on delete cascade,
 title text not null,
 severity text not null check (severity in ('info','low','medium','high','critical')),
 confidence text not null check (confidence in ('low','medium','high')),
 status text not null default 'suspected' check (status in ('suspected','confirmed','false_positive','accepted_risk')),
 affected_asset text not null,
 evidence jsonb not null default '{}'::jsonb,
 impact text,
 remediation text,
 created_at timestamptz not null default now()
);
create table if not exists public.audit_events (
 id bigint generated always as identity primary key,
 workspace_id uuid references public.workspaces(id) on delete cascade,
 actor_id uuid references auth.users(id) on delete set null,
 event_type text not null,
 object_id uuid,
 details jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now()
);

create index if not exists assets_workspace_idx on public.assets(workspace_id);
create index if not exists jobs_workspace_created_idx on public.analysis_jobs(workspace_id, created_at desc);
create index if not exists findings_job_idx on public.findings(job_id);

alter table public.workspaces enable row level security;
alter table public.assets enable row level security;
alter table public.analysis_jobs enable row level security;
alter table public.findings enable row level security;
alter table public.audit_events enable row level security;

create policy "owner reads workspace" on public.workspaces for select to authenticated
 using (owner_id = (select auth.uid()));
create policy "user creates workspace" on public.workspaces for insert to authenticated
 with check (owner_id = (select auth.uid()));
create policy "owner updates workspace" on public.workspaces for update to authenticated
 using (owner_id = (select auth.uid())) with check (owner_id = (select auth.uid()));

create policy "owner reads assets" on public.assets for select to authenticated using (
 exists (select 1 from public.workspaces w where w.id = workspace_id and w.owner_id = (select auth.uid()))
);
create policy "owner creates unverified assets" on public.assets for insert to authenticated with check (
 created_by = (select auth.uid())
 and authorization_confirmed = false
 and allowed_tests = array['passive']::text[]
 and exists (
  select 1 from public.workspaces w where w.id = workspace_id and w.owner_id = (select auth.uid())
 )
);
-- Asset authorization and scope changes are server-only; authenticated clients have no UPDATE policy.

create policy "owner reads jobs" on public.analysis_jobs for select to authenticated using (
 exists (select 1 from public.workspaces w where w.id = workspace_id and w.owner_id = (select auth.uid()))
);
create policy "user queues authorized non-active job" on public.analysis_jobs for insert to authenticated with check (
 requested_by = (select auth.uid())
 and approved_at is null
 and approved_by is null
 and status = 'queued'
 and started_at is null
 and finished_at is null
 and mode in ('passive','static','reverse_engineering')
 and exists (
  select 1 from public.workspaces w where w.id = workspace_id and w.owner_id = (select auth.uid())
 )
 and exists (
  select 1 from public.assets a where a.id = asset_id and a.workspace_id = workspace_id
   and a.authorization_confirmed = true and (a.expires_at is null or a.expires_at > now())
 )
);

create policy "owner reads findings" on public.findings for select to authenticated using (
 exists (select 1 from public.analysis_jobs j join public.workspaces w on w.id = j.workspace_id
  where j.id = job_id and w.owner_id = (select auth.uid()))
);
create policy "owner reads audit" on public.audit_events for select to authenticated using (
 exists (select 1 from public.workspaces w where w.id = workspace_id and w.owner_id = (select auth.uid()))
);

-- Approval, asset authorization, job status changes, finding inserts, and audit writes are server-only.


-- Private bucket for authorized APK uploads. Objects are written only by the API service role.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('apk-uploads', 'apk-uploads', false, 157286400, array['application/vnd.android.package-archive','application/octet-stream'])
on conflict (id) do update set public = false, file_size_limit = 157286400;
