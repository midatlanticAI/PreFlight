---
title: Admin routes guarded by client-only auth
slug: admin-route-exposure
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Admin Route Exposure
  - API Route Auth
sources:
  - title: OWASP A01 — Broken Access Control
    url: https://owasp.org/Top10/A01_2021-Broken_Access_Control/
  - title: OWASP A04 — Insecure Design
    url: https://owasp.org/Top10/A04_2021-Insecure_Design/
  - title: CWE-602 — Client-Side Enforcement of Server-Side Security
    url: https://cwe.mitre.org/data/definitions/602.html
summary: A `/admin` route that hides admin UI when the client-side `useUser()` hook says the user isn't admin, but ships the admin API surface to every visitor anyway. The server has to do the check, not the client.
---

## What this is

A Next.js (or similar React SPA) admin route protected like this:

```tsx
// src/pages/admin/index.tsx
export default function Admin() {
  const user = useUser();
  if (!user?.isAdmin) return <Redirect to="/" />;
  return <AdminDashboard />;
}
```

The redirect runs in the browser. So does the `if` check. So does every API call the dashboard would make. The bundle that ships to every visitor contains the admin code path plus the network calls it would issue. A visitor who turns off JavaScript, edits the React state in DevTools, or just opens the network tab and hits the endpoints directly bypasses the entire check.

## Why it matters

The check is not authorization. The check is a visibility filter. Authorization happens on the server, every request, no exceptions. A client-only check means the server is accepting every request the client makes, including the ones a non-admin user shouldn't be able to make.

Common consequences: the admin API exposes user-creation endpoints, billing endpoints, data-export endpoints, settings endpoints, or destructive admin actions. Each one is callable by anyone who finds the URL.

## What the failure looks like

PreFlight scans paths matching admin / dashboard / internal route conventions for:

- A component that gates rendering on `useUser`, `useSession`, `useAuth`, or similar client hooks.
- The absence of a server-side `getServerSideProps` / route-handler / middleware check on the matching API surface.

Marketing preview paths (e.g., `admin-preview`, `/marketing/admin`) are excluded; those are intentionally public mockups.

## What the fix looks like

Move the check to the server boundary.

**For Next.js App Router**, use middleware plus a server component:

```ts
// middleware.ts
import { NextResponse } from 'next/server';
import { jwtVerify } from 'jose';

export async function middleware(req) {
  const token = req.cookies.get('session')?.value;
  if (!token) return NextResponse.redirect(new URL('/login', req.url));
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(process.env.JWT_SECRET));
    if (!payload.isAdmin) return NextResponse.redirect(new URL('/', req.url));
  } catch {
    return NextResponse.redirect(new URL('/login', req.url));
  }
}

export const config = { matcher: '/admin/:path*' };
```

```tsx
// app/admin/page.tsx — only reached if middleware passed
export default async function Admin() {
  // Trust the middleware. Do not re-check on the client.
  return <AdminDashboard />;
}
```

**For Pages Router**, use `getServerSideProps`:

```tsx
export async function getServerSideProps(ctx) {
  const user = await getUserFromCookie(ctx.req);
  if (!user?.isAdmin) {
    return { redirect: { destination: '/', permanent: false } };
  }
  return { props: { user } };
}
```

**Every API route in the admin surface needs its own check** regardless. The middleware protects the page; the API endpoints need their own server-side authorization on every request because they can be called directly.

```ts
// app/api/admin/users/route.ts
export async function GET(req: Request) {
  const user = await getUserFromCookie(req);
  if (!user?.isAdmin) return new Response('Forbidden', { status: 403 });
  // ... return users
}
```

## Related

- [API route auth](/learn/patterns/api-route-auth) covers the same discipline applied to bare API endpoints.
- [Auth weaknesses](/learn/patterns/auth-weakness) covers the JWT-verification primitives the middleware depends on.
- [Client auth storage](/learn/patterns/client-auth-storage) covers where the session token should and should not live.

## Sources

OWASP A01:2021 ranks broken access control as the most prevalent vulnerability. CWE-602 names the specific class of "client-side enforcement of server-side security." The OWASP A04 insecure-design entry covers the broader architectural mistake.
