---
title: Backend API
slug: backend-api
type: shape
last_updated: 2026-05-15
draft: false
related_probe_ids:
  - Architecture
related_incident_slugs: []
sources:
  - title: OWASP API Security Top 10
    url: https://owasp.org/API-Security/editions/2023/en/0x00-header/
  - title: CWE-89 — SQL Injection
    url: https://cwe.mitre.org/data/definitions/89.html
summary: An Express/Fastify/Koa server with no front end. This is the shape where the security probes bite hardest, because every input is remote, untrusted, and arrives without a human in front of it.
---

## What this shape is

A server: Express, Fastify, or Koa, no frontend framework. The
classifier detects the server framework with no UI and reports it as a
Backend API.

## Scanner behavior

PreFlight classifies this shape (informational). It does not raise a
shape-specific finding for it, but this is the shape where the
injection, secret, TLS, and token-verification probes matter most: a
backend has no UI to hide behind and every request is attacker-shaped.

## The failure mode: there is no client to trust

A backend's entire input surface is the network. The vibe-coded
failures cluster where untrusted input meets a dangerous sink:

- A query built by interpolating a request value is SQL injection
  (XL-002). There is no front-end validation that helps; the request
  did not come from your form.
- A JWT accepted without verifying its signature, or with `alg: none`,
  is total authentication bypass (XL-013). The token did not come from
  a friendly client either.
- A hardcoded credential in server source is the keys to the data, and
  the server is the thing holding the data (XL-006).
- TLS verification disabled on an outbound call turns the server into a
  man-in-the-middle's relay (XL-004).
- Missing authorization checks on a route are invisible without a UI to
  reveal the missing button: the endpoint is just reachable.

## When the shape is fine

A backend API is the correct shape for anything with shared state or
secrets that must not live on the client. It is safe when every input
is treated as hostile: parameterized queries, verified tokens,
secrets from the environment, authorization on every route, TLS left
on.

## Related

- [Raw query interpolation](/learn/patterns/xl-raw-query-interpolation),
  [Authentication and token verification weakness](/learn/patterns/xl-auth-token-verification),
  and [API Route Auth](/learn/patterns/api-route-auth) are the
  load-bearing ones for this shape.
