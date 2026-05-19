---
title: API routes without server-side auth
slug: api-route-auth
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - API Route Auth
  - Admin Route Exposure
sources:
  - title: OWASP A01 — Broken Access Control
    url: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - title: OWASP API Security Top 10
    url: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  - title: CWE-306 — Missing Authentication for Critical Function
    url: https://cwe.mitre.org/data/definitions/306.html
summary: Sensitive API routes (especially destructive verbs DELETE / PUT / PATCH) that ship without a server-side auth check. The client is supposed to call this, sure, but anything on the public internet can call it too.
---

## What this is

An API route handler with no authorization check:

```ts
// app/api/users/[id]/route.ts — no auth check on a destructive DELETE
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await db.users.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
```

```ts
// app/api/admin/promote/route.ts — privilege escalation as a free service
export async function POST(req: Request) {
  const { userId } = await req.json();
  await db.users.update({ where: { id: userId }, data: { role: 'admin' } });
  return Response.json({ ok: true });
}
```

Anyone who can issue an HTTP request can call these. The frontend's "you must be logged in" UI does nothing; the API does not see the UI.

## Why it matters

The frontend is one of many possible clients. `curl`, Postman, an attacker's browser tab, a search engine bot, all hit the same endpoint. Authorization that lives in the React component is decorative. Authorization that lives in the route handler is real.

The common shape: an app ships login, the developer reasons "the admin section is gated by login," forgets that the API routes for the admin section have no check, and ships `POST /api/admin/promote` callable by anyone who guesses the URL.

## What the failure looks like

PreFlight scans server route handlers for:

- Destructive HTTP methods (`DELETE`, `PUT`, `PATCH`) with no auth function call in the handler body.
- Handlers under `admin`, `dashboard`, `internal` paths with no auth function call.
- `jwt.verify(token)` with one argument (no secret) being treated as auth. (`jwt.verify(token, secret)` with 2+ args is recognized as a legitimate check.)

## What the fix looks like

Every route handler that touches data starts with an auth check.

```ts
// app/api/users/[id]/route.ts
import { getServerSession } from '@/lib/auth';

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession(req);
  if (!session) return new Response('Unauthorized', { status: 401 });
  if (session.userId !== params.id && !session.isAdmin) {
    return new Response('Forbidden', { status: 403 });
  }
  await db.users.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
```

For admin-only routes:

```ts
const session = await getServerSession(req);
if (!session?.isAdmin) return new Response('Forbidden', { status: 403 });
```

The discipline that scales: write `getServerSession()` (or equivalent) once, call it as the first line of every handler. Most frameworks support route-level middleware that runs the check uniformly across a route group.

## Related

- [Admin route exposure](/learn/patterns/admin-route-exposure) covers the page-level companion pattern.
- [Auth weaknesses](/learn/patterns/auth-weakness) covers the JWT-verification details the auth check depends on.
- [Cookie security](/learn/patterns/cookie-security) covers where the session token typically lives.

## Sources

OWASP A01:2021 and the OWASP API Security Top 10 both treat missing authorization as the most prevalent application risk. CWE-306 names the specific class.
