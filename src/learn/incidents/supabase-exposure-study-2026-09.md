---
title: '16,326 Supabase Databases Answered a Request for the users Table'
slug: 'supabase-exposure-study-2026-09'
type: 'incident'
last_updated: '2026-10-28'
summary: 'In late September 2026 an internet-wide study took the Supabase project URL and anon key that thousands of sites publish in their JavaScript, asked each database for a table called users, and 16,326 of roughly 300,000 domains handed back rows. More than half held personal information; a smaller share exposed passwords and auth tokens. No product flaw: Row Level Security is on by default for tables made in the dashboard, and off for tables created programmatically, which is the route a coding agent takes.'
draft: false
campaign: 'Supabase RLS exposure'
attack_date: '2026-09-25'
related_probe_ids:
  - 'Supabase RLS'
  - 'Secret Scanner'
related_incident_slugs:
  - agents-md-downloads-2026-10
sources:
  - title: 'Cybernews: 16,000 Supabase databases exposed as vibe-coded apps leak sensitive user data'
    url: 'https://cybernews.com/news/16000-supabase-databases-exposed/'
  - title: 'Supabase docs: Row Level Security'
    url: 'https://supabase.com/docs/guides/database/postgres/row-level-security'
  - title: 'Supabase docs: Securing your API (anon key, service role, RLS)'
    url: 'https://supabase.com/docs/guides/api/securing-your-api'
  - title: 'CVE-2025-48757, the Lovable-built app class of the same failure'
    url: 'https://nvd.nist.gov/vuln/detail/CVE-2025-48757'
  - title: 'CWE-284, Improper Access Control'
    url: 'https://cwe.mitre.org/data/definitions/284.html'
---

# 16,326 Supabase Databases Answered a Request for the users Table

The method in the study was the method an attacker uses, and it is three steps. Find the Supabase project URL and anon key in a site's JavaScript bundle, where they are meant to be. Send one REST request: `GET /rest/v1/users?select=*` with that key. Read what comes back.

Against roughly 300,000 domains, 16,326 came back with rows. About one in eighteen. The researchers described the exposed apps by category rather than name and followed disclosure practice instead of publishing a list, so the count is the finding: more than half of those databases appeared to hold personal information about real people, a smaller share exposed passwords or authentication tokens, and a few held partial payment data. The scan did not confirm breaches or count affected people; it counted tables that answered.

## Why the anon key is not the problem

The anon key is public by design. It ships in the bundle, and Supabase's own documentation says so: it identifies the project, and Row Level Security is what decides which rows a request holding it can see. A table with RLS enabled and no policies returns nothing to the anon role. A table with RLS disabled returns everything.

The study's explanation of the gap is the part that matters for anyone building with an agent. Supabase enables RLS by default for tables created through the dashboard. Tables created programmatically, through SQL run by a migration tool or a coding agent, do not get it unless the SQL says so. An agent asked to "add a users table" writes `create table users (...)` and moves on; nothing in that statement turns RLS on, and nothing in the dashboard flags that it is off. Supabase's position, that projects are secure by default and configuration is shared responsibility, is accurate and is also exactly where the 16,326 came from.

This is the CVE-2025-48757 class from January, measured across the whole internet instead of one builder's showcase. Same cause, same request, same fix.

## If your app uses Supabase, read this first

1. **Run the attacker's request against yourself.** Take the URL and anon key from your own bundle and `curl` the REST endpoint for every table name in your schema. Anything that returns rows is the incident.
2. **Enable RLS on every table in the public schema**, including the ones that "only the server touches". The service role bypasses RLS; the anon key does not, and the anon key is public.
3. **Write a policy per operation.** `USING (auth.uid() = user_id)` for select, the same `WITH CHECK` for insert and update. A table with RLS on and no policy is locked, which is the correct starting state.
4. **Put it in the migration.** A policy created in the dashboard is a decision nobody can review. `alter table public.users enable row level security;` in a migration file is one that ships with the code and survives the next environment.
5. **Rotate anything a readable table exposed.** Password reset tokens, API keys, session rows. The table being closed now does not recall the copies.

## What PreFlight checks

The **Supabase RLS** probe reads the migrations in the repository and reports a `create table` with no matching `enable row level security`, and reads the client code for every `.from('table')` call against a table nothing in the repository protects. It is the migration-file view of the study's request: the tables the code reaches and the SQL that never turned the lock on.

Two things it will not do, on purpose. It cannot see RLS that was enabled in the dashboard, so the client-read finding says that, and leads with the ten-second way to check. And since October 28 it no longer reports a SQLite or MySQL schema as missing a Postgres feature; a D1 project with fifty tables was getting fifty criticals for a setting its engine does not have.

## The lesson

The study did nothing clever. It used the key the apps published, asked for the table the apps named, and the databases answered because a statement that an agent writes in one line does not include the one clause that would have stopped it. Filtering in the query is not protection; the client sends the query. RLS is the only part of this the user cannot edit, and it has to be in the migration, where the next reader can see it is there.
