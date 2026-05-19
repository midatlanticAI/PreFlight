---
title: Supabase Row-Level Security misconfigurations
slug: supabase-rls
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Supabase RLS
  - Secret Scanner
related_incident_slugs: []
sources:
  - title: Supabase Docs — Row Level Security
    url: https://supabase.com/docs/guides/database/postgres/row-level-security
  - title: Supabase Docs — Auth helpers
    url: https://supabase.com/docs/guides/auth
  - title: PostgreSQL Docs — Row Security Policies
    url: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
  - title: CWE-285 — Improper Authorization
    url: https://cwe.mitre.org/data/definitions/285.html
  - title: OWASP A01 — Broken Access Control
    url: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
summary: Supabase tables created without `enable row level security` plus permissive `using (true)` policies. The most common access-control failure in AI-tooled Supabase apps, and the one that ships a publicly readable database without anyone noticing.
---

## What this is

Supabase exposes a Postgres database through a single REST/PostgREST endpoint plus a JavaScript client. Every browser request to that endpoint carries an API key. There are two keys: the `anon` key (intentionally public, ships in the browser bundle) and the `service_role` key (bypasses all access control, never meant to leave the server).

The `anon` key is designed to work against a database protected by Row-Level Security (RLS). RLS is a Postgres feature where every row of a table has a policy that says "this row is readable / writable by this principal." When RLS is enabled on a table, the database itself decides which rows the anon client can see, based on policies you write.

When RLS is NOT enabled, the database falls back to its default behavior: any role with the table's grant can read every row. The `anon` role has `SELECT` granted on tables by default in Supabase, so an RLS-off table is fully readable by any browser holding the anon key.

The full failure: a table is created via Supabase's schema editor or a migration, the developer forgets to enable RLS, the anon client reads every row, the database is public.

## Why it matters

The blast radius is the whole table. Not "rows the user shouldn't see," not "rows belonging to other users." Every row.

A typical schema after a vibe-built CRUD session:

```sql
create table users (
  id uuid primary key,
  email text,
  hashed_password text,
  stripe_customer_id text,
  api_key text,
  is_admin boolean default false,
  created_at timestamptz default now()
);

create table messages (
  id uuid primary key,
  user_id uuid references users(id),
  body text,
  created_at timestamptz default now()
);
```

Without RLS enabled, the production anon key in the page bundle, plus a one-line fetch in DevTools, reads the entire `users` table including hashed passwords, Stripe customer IDs, and any API keys stored as text. The `messages` table reads every private message ever sent. No authentication required, no auth bypass needed, no clever exploit. The database is a public API at that point.

Three reasons this happens most often in AI-built apps:

**RLS-off works in development.** A solo developer logging in as a single user against their own local supabase instance never notices that the anon client can read everything, because there is only one set of rows to read and they belong to the developer. The failure mode only appears when a second user signs up in production.

**The Supabase schema editor does not enable RLS by default.** Creating a table through the dashboard ships it RLS-off. The dashboard surface a warning, but the warning is a yellow bar that gets dismissed. The default-enabled behavior is something the developer must opt into.

**Writing a correct policy is non-trivial.** Even developers who enable RLS often write `USING (true)` because the first error message they hit is "policy returned no rows." The fix-the-error path of least resistance is a permissive policy. A permissive policy is, in access-control terms, the same thing as RLS-off.

## What the failure looks like

PreFlight scans Supabase migration files (`supabase/migrations/*.sql`) and the schema-policy files often committed alongside them. Three findings:

**Table created without `enable row level security`.** A `CREATE TABLE foo (...)` statement with no subsequent `ALTER TABLE foo ENABLE ROW LEVEL SECURITY;` in the same file. (Multi-file sequences are allowed; PreFlight only flags when the same file creates a table and never enables RLS for it.)

**Permissive policy.** A `CREATE POLICY ... USING (true)` is functionally equivalent to no RLS. Same for `WITH CHECK (true)` on insert/update policies.

**Service-role key in client code.** The `service_role` key in `process.env.SUPABASE_SERVICE_ROLE_KEY` is fine on the server. The same key in `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY` or hardcoded in a `.tsx` file is the entire database to anyone with DevTools. See the [NEXT*PUBLIC* misuse pattern](/learn/patterns/next-public-misuse) for the broader class.

## What the fix looks like

Three motions.

**Enable RLS on every table by default.**

The migration template every Supabase project should ship with:

```sql
-- Every new table: enable RLS at creation.
create table messages (
  id uuid primary key,
  user_id uuid references auth.users (id) not null,
  body text,
  created_at timestamptz default now()
);
alter table messages enable row level security;

-- Then write the access-control policies. Note: deny-by-default is automatic
-- once RLS is on. The policies grant access; absence of a policy denies.
create policy "read own messages" on messages
  for select
  using (auth.uid() = user_id);

create policy "insert own messages" on messages
  for insert
  with check (auth.uid() = user_id);

create policy "update own messages" on messages
  for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "delete own messages" on messages
  for delete
  using (auth.uid() = user_id);
```

The pattern repeats per table. The policies vary by table semantics: a `comments` table on a public blog post needs a different `select` policy than a `messages` table with private threads. The discipline that matters: every table gets RLS enabled, then explicit policies, in the same migration that creates it. Reviewing the migration before merge catches the case where a developer forgot.

**Audit existing tables.**

```sql
-- Lists every table in the public schema and whether RLS is on.
select schemaname, tablename, rowsecurity
from pg_tables
where schemaname = 'public'
order by tablename;
```

Any row with `rowsecurity = false` is a finding. Enable RLS on those tables, then write the policies before allowing the anon client to hit them. If the table is one no client should ever read directly (an internal job queue, an audit log), the answer is RLS-on with zero policies, which produces deny-all.

```sql
alter table sensitive_internal_table enable row level security;
-- No policies follow. Anon and authenticated roles cannot read, write, update, or delete.
-- Service role still has full access because RLS does not apply to it.
```

**Keep the service-role key on the server.**

The service role bypasses RLS by design. Every server-side action that needs to operate without policy constraints (e.g., a scheduled cleanup job, a webhook handler that updates user data) reaches for the service-role client. Every browser-side action uses the anon client and gets policy-checked.

```ts
// lib/supabase-server.ts (server-only)
import { createClient } from '@supabase/supabase-js';
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // server-only, NO NEXT_PUBLIC_ prefix
);

// lib/supabase-browser.ts (client + server, but never receives service role)
import { createClient } from '@supabase/supabase-js';
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY // intentionally public
);
```

The two clients live in two different files so the `lib/supabase-server.ts` symbol can never be imported by a client component (it would produce a build-time error). The `lib/supabase-browser.ts` symbol is safe to import anywhere.

## A worked example of a policy that is correct without being trivial

A multi-tenant SaaS where users belong to organizations, and an organization's data is readable by any member of that organization:

```sql
create table organizations (
  id uuid primary key,
  name text
);
alter table organizations enable row level security;

create table memberships (
  user_id uuid references auth.users (id) not null,
  org_id uuid references organizations (id) not null,
  role text check (role in ('owner', 'admin', 'member')),
  primary key (user_id, org_id)
);
alter table memberships enable row level security;

create table documents (
  id uuid primary key,
  org_id uuid references organizations (id) not null,
  title text,
  body text
);
alter table documents enable row level security;

-- Policy: a user can read documents from any org they're a member of.
create policy "read org documents" on documents
  for select
  using (
    exists (
      select 1 from memberships m
      where m.user_id = auth.uid()
        and m.org_id = documents.org_id
    )
  );

-- Policy: only admins and owners can write.
create policy "write org documents" on documents
  for all
  using (
    exists (
      select 1 from memberships m
      where m.user_id = auth.uid()
        and m.org_id = documents.org_id
        and m.role in ('admin', 'owner')
    )
  )
  with check (
    exists (
      select 1 from memberships m
      where m.user_id = auth.uid()
        and m.org_id = documents.org_id
        and m.role in ('admin', 'owner')
    )
  );

-- Memberships need their own policies. The most common bug is RLS-on on
-- documents but RLS-off on memberships, which lets a logged-in user enumerate
-- every membership in the database. Defense in depth: every table.
create policy "read own memberships" on memberships
  for select
  using (user_id = auth.uid());
```

The pattern: every read path through a foreign key requires that the joined table is also RLS-protected and that its policy aligns with the principal's access. A single permissive table breaks the chain.

## Related

- [NEXT*PUBLIC* misuse](/learn/patterns/next-public-misuse) covers the service-role-key-in-client-bundle failure mode that breaks RLS even when RLS is configured correctly.
- [Hardcoded secrets in source](/learn/patterns/secret-scanner) covers the broader class for any credential that leaks via source-tracked files.

## Sources

The Supabase RLS docs and the Postgres row-security docs are the authoritative references. CWE-285 names the vulnerability class. OWASP A01:2021 ranks broken access control as the highest-prevalence application security risk, and Supabase's RLS-off default is one of the cleanest examples of how this happens to teams that "did set up auth."
