---
title: Server-rendered app (SSR)
slug: ssr
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: Next.js — server-only
    url: https://nextjs.org/docs/app/building-your-application/rendering/composition-patterns#keeping-server-only-code-out-of-the-client-environment
  - title: OWASP — Sensitive Data Exposure
    url: https://owasp.org/www-project-top-ten/
  - title: CWE-200 — Exposure of Sensitive Information
    url: https://cwe.mitre.org/data/definitions/200.html
summary: Next.js, Remix, or SvelteKit rendering on the server. The defining failure mode is the server/client boundary: code that was supposed to stay on the server ending up in the bundle the browser downloads, secrets and all.
---

## What this shape is

An app that renders on the server per request: Next.js, Remix,
SvelteKit. The Architecture probe classifies it as SSR (for example,
Next.js without a static export) and emits an informational finding
because the shape is a choice, not a defect. What it points at is the
one discipline this shape lives or dies on.

## Scanner behavior

Pre-Flight flags this shape: the Architecture probe raises an
informational finding on the server/client boundary, and the
`NEXT_PUBLIC_` / Secret Scanner / Client Auth Storage probes catch the
concrete leaks. It is one of the four shapes the scanner acts on, not
only classifies.

## Why AI defaults to it

The starter for every major framework is server-rendered, so "build me
an app" produces an SSR app by default. The framework hands you a single
mental space where server and client code sit side by side in the same
files. That ergonomic is the whole appeal, and it is also the trap.

## Why the server/client boundary is the security model

In an SSR app the boundary between "runs on the server" and "ships to
the browser" is invisible in the editor and absolute in production. When
it is crossed the wrong way, the failure is not a bug, it is disclosure:

- A server-only module imported into a Client Component pulls its
  contents into the client bundle. A database client, a signing helper,
  an API key constant: now downloadable by anyone who opens dev tools.
  This is the manifesto's opening example, and SSR is the shape that
  produces it most often.
- The `NEXT_PUBLIC_` (or framework-equivalent) prefix is a loaded
  footgun. It does exactly what it says, ships the value to the client,
  and the name does not warn a vibe coder that "public" means "in every
  visitor's browser."
- Edge runtime is not Node. Code that reaches for `fs`,
  `crypto.randomBytes`, or other Node APIs fails or behaves differently
  there, and the difference tends to surface as a half-working security
  primitive rather than a clean crash.

## What the scanner sees and says

The Architecture probe emits an SSR best-practices finding, and the
`NEXT_PUBLIC_` Misuse, Secret Scanner, and Client Auth Storage probes
catch the concrete leaks. The Architecture finding is informational on
purpose: the shape is fine, the boundary discipline is what has to be
deliberate.

## How to keep the boundary real

- Mark server-only code as server-only: the `server-only` import in
  Next.js, or an enforced `/server/` directory convention. Make the
  boundary mechanical, not a thing you remember.
- Credentials, database access, and PII helpers live only on
  server-only paths. Never behind a `NEXT_PUBLIC_`-style prefix.
- Server Components by default; Client Components only for the
  interactive islands that need them. Every client boundary is a place
  a server import can leak through, so minimize them.
- If you stream responses, make data fetches promise-aware up front;
  streaming changes when code runs, which changes what is safe to
  assume about it.
- Know your runtime. If you deploy to the edge, do not assume Node
  APIs; verify the security-relevant ones (randomness, hashing) work
  there.

## When the simpler shape is better

If the app has no per-request server logic, a static export or an SSG
build removes the entire class of boundary-leak risk by removing the
server. Reach for SSR when you need per-request rendering, not because
the starter defaulted to it.

## Related

- [`NEXT_PUBLIC_` Misuse](/learn/patterns/next-public-misuse) and
  [Secret Scanner](/learn/patterns/secret-scanner) cover the exact leaks
  this boundary failure produces.
- [Static HTML with a build tool](/learn/shapes/static-html-build) is
  the shape to drop to when there is no server logic to justify SSR.
