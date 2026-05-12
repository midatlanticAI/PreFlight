---
title: Hardcoded secrets in source
slug: secret-scanner
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Secret Scanner
related_incident_slugs:
  - sapphire-sleet-axios-2026-03
  - mini-shai-hulud-tanstack-2026-05
sources:
  - title: OWASP A02 — Cryptographic Failures
    url: https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
  - title: OWASP A07 — Identification and Authentication Failures
    url: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - title: CWE-798 — Use of Hard-coded Credentials
    url: https://cwe.mitre.org/data/definitions/798.html
  - title: GitHub Docs — Removing sensitive data from a repository
    url: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
  - title: AWS Docs — What to do if you inadvertently expose an AWS access key
    url: https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html
summary: AWS, Stripe, OpenAI, Anthropic, GitHub, and private-key material committed to source. Why it is catastrophic, why AI coding tools produce it often, and what to do once a key has touched git.
---

## What this is

A secret in source is an API key, token, password, or private key written as a literal string inside a file that gets committed to version control. The most common shapes:

```js
const STRIPE = "sk_live_<your-key-here>"; // production charge access
const OPENAI = "sk-proj-Abc1234567890DEFGHijklmno";
const SUPABASE = "postgres://admin:hunter2@db.internal:5432/prod";
```

```python
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
```

Any of those shapes inside a tracked file is the pattern. It does not matter whether the file is named `secrets.js`, `config.ts`, `notes.md`, or `temp.py`. The git index sees the bytes. Once the bytes are pushed, the key is on every clone, every fork, every CI cache, and every search-engine crawler that knows where to look.

## Why it matters

Three reasons in order of immediacy:

**Compromise is not a probability, it is a measurement.** Public GitHub gets scanned by automated harvesters in seconds. Anthropic, OpenAI, Stripe, and AWS run their own scanners and quarantine matching keys before you finish the push. A key in a public repo has minutes of useful life. A key in a private repo has the lifespan of whichever third-party tool gets compromised next.

**Git history is forever.** Removing a key with `git rm` and committing the removal does not remove it from history. The key lives on in every prior commit, every reflog, every fork, every cache. Removing it from history (via `git filter-repo` or BFG) requires force-pushing main, which breaks every clone, and still does not recall the bytes from the world's mirrors. Rotation is the only fix. Scrubbing is a cleanup, not a remediation.

**The blast radius depends on the key's scope, not its severity.** A `sk_test_` key sounds harmless until you find out a test account had access to a live customer database. A `read-only` token sounds fine until it can read PII. A "developer" GitHub token can have org-admin scopes if the developer is an org admin. The grade of the key is what the key actually grants on the day it leaks, not what it was supposed to grant on the day it was created.

## What the failure looks like

The shapes Pre-Flight scans for:

| Provider | Shape | Notes |
|---|---|---|
| AWS access key ID | `AKIA[0-9A-Z]{16}` | Always paired with a secret key in any real config |
| AWS secret key | base64-shaped, 40 chars | Often near "secret_access_key" or in env vars |
| Stripe live | `sk_live_[A-Za-z0-9]{24,}` | Production charge access |
| Stripe test | `sk_test_...` | Can still touch a live data set if test mode was misconfigured |
| OpenAI | `sk-[A-Za-z0-9]{20,}` or `sk-proj-...` | Modern format is `sk-proj-` |
| Anthropic | `sk-ant-[A-Za-z0-9_-]{20,}` | Distinguishable by the `-ant-` segment |
| Google | `AIza[A-Za-z0-9_-]{30,}` | Maps API, Gemini API, and others |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` (classic) or `gho_` (OAuth) | Newer fine-grained tokens are `github_pat_` |
| Slack | `xox[bpas]-...` | Bot, user, admin variants by prefix |
| Hugging Face | `hf_[A-Za-z0-9]{30,}` | Model + inference access |
| Replicate | `r8_[A-Za-z0-9]{30,}` | API access |
| Database URL with creds | `postgres://user:pass@host` | `mysql://`, `mongodb://`, and others follow the same pattern |
| Private key block | `-----BEGIN ... PRIVATE KEY-----` | RSA, EC, PGP, OpenSSH all match |

Pre-Flight skips files it can identify as deliberate test fixtures (paths matching `*.test.*`, `*.spec.*`, `tests/`, `__tests__/`), markdown documentation files where the key is part of an example, and Pre-Flight's own threat-intel manifests (where the patterns are listed as detection rules, not as live keys).

## Why AI coding tools produce this

The training data is full of `.env`-replacement examples written for tutorials. A model asked "wire up Stripe" reaches for the shape it has seen most often, which is the shape where the secret is a literal next to the import. The model does not know which secrets are server-only and which are client-safe. It does not know whether the file will be committed. It pattern-completes the structure of working code, and the structure of working code in the training set frequently includes a literal credential.

The viber pasting the output has no built-in step that says "the key in this snippet needs to move." If the code runs, the key looks like it works. The key works. The key keeps working until it leaks.

## What the fix looks like

Three motions, in order.

**Treat the leaked key as compromised. Rotate first, scrub after.**

```bash
# AWS
aws iam create-access-key --user-name <user>      # mint a replacement first
aws iam delete-access-key --access-key-id AKIA... # only then revoke

# Stripe
# Dashboard > Developers > API keys > Roll key (one click; old key dies)

# OpenAI / Anthropic
# Dashboard > API keys > Revoke; then create a new one

# GitHub PAT
gh auth refresh -s admin:org  # mint scoped replacement
# Then revoke at github.com/settings/tokens
```

A rotation that succeeds replaces every consumer of the key (your app's env vars, your CI's secrets, your local `.env.local`, the password manager note where you keep it) and then revokes the old credential. Skipping the replacement step risks an outage; skipping the revocation step leaves the leaked credential live.

**Move the key out of source and into the right channel.**

For runtime-injectable secrets (most secrets), the file is `.env` (not committed, mentioned in `.gitignore`) plus an `.env.example` with empty values that is committed:

```
# .env (not in git)
STRIPE_SECRET_KEY=sk_live_...
OPENAI_API_KEY=sk-...

# .env.example (in git)
STRIPE_SECRET_KEY=
OPENAI_API_KEY=
```

Server-only code reads `process.env.STRIPE_SECRET_KEY` directly. The browser bundle never sees the value. If you are on Next.js and need an env var that is intentionally public (a Supabase anon key, a public Maps API key with referer restrictions), the `NEXT_PUBLIC_` prefix is the mechanism for that. Anything without the prefix stays server-only. Never put a server-only secret behind the `NEXT_PUBLIC_` prefix as a shortcut.

For longer-lived secrets and team workflows, a managed secret store is the upgrade: AWS Secrets Manager, GCP Secret Manager, Vercel Environment Variables, Doppler, 1Password Secrets Automation, or whatever fits the host. The store rotates, audit-logs reads, and gives the app a per-environment view (prod gets prod values, preview branches get preview values).

**Pre-commit, not post-commit.** Once a secret is in git history, the best you can do is rotate. The cheap upgrade is a hook that refuses to commit a file matching any of the patterns above:

```bash
# .git/hooks/pre-commit (or a managed hook via pre-commit / lefthook / husky)
git diff --cached -U0 | grep -E 'AKIA[0-9A-Z]{16}|sk_live_|sk-proj-|-----BEGIN.*PRIVATE KEY-----' && {
  echo "secret-shape detected in staged changes; refusing commit"
  exit 1
}
```

A second layer is a CI step that runs the same check on the PR diff, so a developer who skipped the hook still gets caught before merge.

## Related

- [NEXT_PUBLIC_ misuse](/learn/patterns/next-public-misuse) explains the specific Next.js footgun for client-bundle key exposure.
- [package.json supply-chain hooks](/learn/patterns/package-json-supply-chain) covers the install-time execution surface that compromised packages use to steal keys after a successful key leak.
- [Sapphire Sleet axios incident](/learn/incidents/sapphire-sleet-axios-2026-03) is the March 2026 case where a compromised npm package exfiltrated npm + GitHub tokens via a postinstall script.

## Sources

The reference links above. Notable docs in priority order:

- CWE-798 names the vulnerability class.
- OWASP A02:2021 covers cryptographic failures (which secrets-in-source feed into).
- OWASP A07:2021 covers identification and authentication failures (which secrets-in-source enable).
- GitHub's "Removing sensitive data from a repository" doc is the authoritative source on why scrubbing history is not a remediation.
- AWS's access-key best-practices doc carries the same rotation-first sequence for AWS specifically.
