---
title: NEXT_PUBLIC_ env-var leakage
slug: next-public-misuse
type: pattern
last_updated: 2026-05-12
draft: true
related_probe_ids:
  - NEXT_PUBLIC_ Misuse
sources:
  - title: Next.js environment variables
    url: https://nextjs.org/docs/app/building-your-application/configuring/environment-variables
  - title: CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
    url: https://cwe.mitre.org/data/definitions/200.html
summary: Server-only secrets accidentally prefixed with `NEXT_PUBLIC_` and shipped to the browser bundle. AI tools love to do this when stitching auth code.
---

> _Draft — content coming soon._
>
> Will cover: the Next.js convention (NEXT*PUBLIC* inlines at build time into
> the client bundle), the two failure shapes (secret-named variable, secret-
> shaped value), the safe pattern (`process.env.X` on the server only), and
> the dev-mode habit of reading `process.env` in `getServerSideProps` /
> route handlers / server components rather than passing it through props.
