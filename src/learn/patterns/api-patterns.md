---
title: API patterns
slug: api-patterns
type: pattern
last_updated: 2026-09-03
draft: false
related_probe_ids:
  - API Patterns
sources:
  - title: 'OWASP API Security Top 10 — Unrestricted Resource Consumption'
    url: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
  - title: 'CWE-307 — Improper Restriction of Excessive Authentication Attempts'
    url: https://cwe.mitre.org/data/definitions/307.html
  - title: 'Express — error handling and responses'
    url: https://expressjs.com/en/guide/error-handling.html
  - title: 'FastAPI — async and blocking work'
    url: https://fastapi.tiangolo.com/async/
summary: The handler-level habits that decide whether an endpoint survives contact with users and abusers. Bodies written to the database unvalidated, login routes with unlimited guesses, list endpoints that return the whole table, handlers that answer twice, and blocking calls inside async Python.
---

## What this is

A route handler is a contract with strangers. Generated handlers tend to honor the happy path of that contract and skip the clauses that only matter under load or attack: what arrives, how often, how much goes back.

## Why it matters

**Unvalidated writes** store whatever arrived: wrong types, missing fields, extra keys later code trusts. One schema parse at the top of the handler turns unknown input into known-shaped data.

**A login route with no rate limit** is unlimited guesses at machine speed. Independent testing of AI-generated apps found working rate limiting almost never ships by default.

**`findMany()` with no limit** works at fifty rows and times out at fifty thousand; the failure arrives together with success.

**Two sends on one path** means execution ran past the first response into code you thought was unreachable.

**A blocking call in an async Python handler** stalls the event loop itself: while one request sleeps, every request waits.

## What the probe does not do

CORS misconfiguration, auth on routes, and injection are owned by their existing probes. Middleware ordering and overfetch judgments need intent a scan cannot read.
