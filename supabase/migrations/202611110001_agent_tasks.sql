create table if not exists public.agent_tasks (
 id uuid primary key default gen_random_uuid(),
 workspace_id uuid not null references public.workspaces(id) on delete cascade,
 asset_id uuid not null references public.assets(id) on delete restrict,
 requested_by uuid not null references auth.users(id) on delete cascade,
 action text not null check (action in ('full-static-suite')),
 objective text not null check (length(objective) between 8 and 1000),
 status text not null default 'proposed' check (status in ('proposed','approved','queued','failed','cancelled')),
 approved_by uuid references auth.users(id),
 approved_at timestamptz,
 analysis_job_id uuid references public.analysis_jobs(id) on delete set null,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create index if not exists agent_tasks_owner_created_idx
 on public.agent_tasks(requested_by, created_at desc);
alter table public.agent_tasks enable row level security;
create policy "owner reads agent tasks" on public.agent_tasks for select to authenticated
 using (requested_by = (select auth.uid()));
-- Writes and approval transitions are server-only through the API service role.
