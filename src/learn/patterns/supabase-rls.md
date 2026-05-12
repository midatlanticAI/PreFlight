---
title: Supabase Row-Level Security misconfigurations
slug: supabase-rls
type: pattern
last_updated: 2026-05-12
draft: true
related_probe_ids:
  - Supabase RLS
sources:
  - title: Supabase RLS docs
    url: https://supabase.com/docs/guides/auth/row-level-security
  - title: CWE-285 — Improper Authorization
    url: https://cwe.mitre.org/data/definitions/285.html
summary: Tables created without `enable row level security` plus permissive `using (true)` policies — the most common AI-tooling pitfall for Supabase apps.
---

> _Draft — content coming soon._
>
> Will cover: why RLS-off is the Supabase equivalent of "public S3 bucket," why
> AI tools default to it (it works in dev), the migration template that flips
> RLS on for every table by default, and the auth-context checklist for writing
> a policy that's both correct and minimum-privilege.
