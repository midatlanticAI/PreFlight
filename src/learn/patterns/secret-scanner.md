---
title: Hardcoded secrets in source
slug: secret-scanner
type: pattern
last_updated: 2026-05-12
draft: true
related_probe_ids:
  - Secret Scanner
sources:
  - title: OWASP A07 — Identification and Authentication Failures
    url: https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/
  - title: CWE-798 — Use of Hard-coded Credentials
    url: https://cwe.mitre.org/data/definitions/798.html
summary: AWS, Stripe, OpenAI, Anthropic, GitHub, and private-key material committed to source — why it's catastrophic and what to do instead.
---

> _Draft — content coming soon._
>
> Will cover: the failure mode (key shipped to public source = key compromised),
> the AI-coding-tooling drift that produces this (Lovable / Cursor / Bolt /
> Replit / Claude Code generating `.env`-replacement constants), the canonical
> fix (env vars + a secrets manager + revocation playbook), and the audit-log
> habit that prevents the recurrence.
