---
title: Monolithic SPA
slug: monolithic-spa
type: shape
last_updated: 2026-05-12
draft: true
sources:
  - title: CWE-1041 — Use of Redundant Code
    url: https://cwe.mitre.org/data/definitions/1041.html
summary: The "everything in App.jsx" shape AI tools default to. Why it's a security risk (not just a maintainability one) and the file-split habit that prevents it.
---

> _Draft — content coming soon._
>
> Will cover: why a 4000-line single-file SPA is a security risk (review fatigue
>
> - test isolation impossible + AI-refactor quality collapses past ~1500 lines),
>   the natural seams to cut on (probes / formatters / history / theme / per-route
>   components), and the "<500 lines per file" habit that keeps the architecture
>   reviewable.
