---
title: .env files tracked in source control
slug: env-file-hygiene
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Env File Hygiene
  - Secret Scanner
sources:
  - title: 12-Factor App — Config
    url: https://12factor.net/config
  - title: GitHub Docs — Removing sensitive data from a repository
    url: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
  - title: CWE-798 — Use of Hard-coded Credentials
    url: https://cwe.mitre.org/data/definitions/798.html
summary: A `.env` file committed to git ships every credential inside it into version history forever. Solved by `.gitignore` plus a companion `.env.example` that documents the schema without the values.
---

## What this is

The `.env` file convention: one file at the project root, key=value lines, loaded at process start. The convention is fine. The failure mode is committing the file.

```
# .env (committed to git — every credential is now in version history)
DATABASE_URL=postgres://admin:hunter2@db.internal:5432/prod
STRIPE_SECRET_KEY=sk_live_FAKE
OPENAI_API_KEY=sk-proj-FAKE
JWT_SECRET=correcthorsebatterystaple
```

Once that file is in any commit (any branch, any fork), the credentials live in git forever. Removing them with a follow-up commit does not remove them from history.

## Why it matters

Every credential committed once is a credential rotated. There is no scrubbing. There is only rotation.

The blast radius equals the union of every credential in the file at the worst commit. For a typical SaaS, that means the database connection string, the payment processor, an LLM provider, an email sender, and the session-signing secret. Each is a distinct rotation event with distinct downstream consequences (logged-out users, paused webhooks, billing alarms).

## What the failure looks like

Pre-Flight flags any tracked `.env` file:

```
.env
.env.local
.env.production
.env.development
.env.staging
```

A `.env.example` (with empty values, documenting the schema) is fine and recommended.

## What the fix looks like

Three motions, in order.

**1. Stop tracking the file.**

```bash
echo '.env' >> .gitignore
echo '.env.local' >> .gitignore
echo '.env.production' >> .gitignore
git rm --cached .env
git commit -m "untrack .env (rotate credentials separately)"
```

**2. Rotate every credential inside the file.** The credentials in the file are leaked. Treat them as compromised, regardless of repo visibility. Mint replacements, update every consumer (CI secrets, dev machines, production env), then revoke the old ones. See [Hardcoded secrets in source](/learn/patterns/secret-scanner) for the rotation playbook per provider.

**3. Commit a `.env.example` that documents the schema.**

```
# .env.example (committed; shows the schema, holds no values)
DATABASE_URL=
STRIPE_SECRET_KEY=
OPENAI_API_KEY=
JWT_SECRET=
```

The example file lets a new developer see what env vars the app needs without granting them production credentials.

## Related

- [Hardcoded secrets in source](/learn/patterns/secret-scanner) covers the broader credential-leak class.
- [NEXT*PUBLIC* misuse](/learn/patterns/next-public-misuse) covers the specific Next.js variant where the `.env` is correctly untracked but the `NEXT_PUBLIC_` prefix exposes the values anyway.

## Sources

The 12-Factor App config principle is the canonical reference for env-var-driven configuration. GitHub's "Removing sensitive data" doc confirms that scrubbing is not a remediation; rotation is. CWE-798 names the vulnerability class.
