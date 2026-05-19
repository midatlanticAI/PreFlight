---
title: Static Site Generator (SSG)
slug: ssg
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: Astro — output modes
    url: https://docs.astro.build/en/basics/rendering-modes/
  - title: Next.js — static exports
    url: https://nextjs.org/docs/app/building-your-application/deploying/static-exports
  - title: CWE-200 — Exposure of Sensitive Information
    url: https://cwe.mitre.org/data/definitions/200.html
summary: A framework that pre-renders to static HTML at build time (Astro static, Next export). No server at request time, but the build is now a trust boundary, and a build-time secret is a shipped secret.
---

## What this shape is

A framework (Astro in static mode, Next.js with `output: export`) that
runs at build time and emits plain pre-rendered HTML/CSS/JS. There is no
server handling requests. The classifier reports it as a Static Site
Generator.

## Scanner behavior

PreFlight classifies this shape (informational). It does not raise a
shape-specific finding for it. The hardening that matters here overlaps
with the static-HTML checklist, and the HTML/SEO/secret probes still
run on the output and the source.

## The failure mode: the build is the boundary

An SSG feels as safe as a static site, and for runtime it is. The risk
moves to build time:

- Data fetched at build is baked into the HTML. If a build-time API
  call returns more than the page should show, the extra data ships in
  the page source, readable by anyone with view-source.
- An environment variable read during the build and interpolated into a
  component is now a literal in the output bundle. "It is only in the
  build env" is not protection once the build writes it into a file.
- Framework hydration still ships JavaScript. Client components in an
  otherwise static site are the same XSS surface as any SPA, and the
  same CSP discipline applies.

## When to use it, when not

SSG is the right shape when content is known at build and does not need
per-request logic: marketing sites, docs, blogs. Reach for SSR only
when a page genuinely must render differently per request; the SSG that
does not need a server is strictly safer because it has no server to
attack.

## Related

- [Static HTML with a build tool](/learn/shapes/static-html-build)
  shares the runtime hardening checklist.
- [Server-rendered app (SSR)](/learn/shapes/ssr) is the shape to use
  only when per-request rendering is actually required.
