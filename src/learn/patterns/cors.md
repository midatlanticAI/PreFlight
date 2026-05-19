---
title: Wildcard CORS (Access-Control-Allow-Origin&#58; *)
slug: cors
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - CORS
sources:
  - title: MDN — Cross-Origin Resource Sharing (CORS)
    url: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
  - title: OWASP Cheat Sheet — CORS
    url: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
  - title: CWE-942 — Permissive Cross-domain Policy with Untrusted Domains
    url: https://cwe.mitre.org/data/definitions/942.html
summary: An API that returns `Access-Control-Allow-Origin&#58; *` invites every origin on the internet to read responses. Combined with cookies, it's worse than no CORS at all.
---

## What this is

CORS controls which origins (other websites) the browser will let read responses from your API. A wildcard:

```js
res.setHeader('Access-Control-Allow-Origin', '*');
```

means every origin on the internet. If the API serves anything not meant to be public (user data, internal metrics, anything keyed by auth), wildcard CORS lets any malicious site read it via a logged-in user's browser.

## Why it matters

Wildcard CORS only blocks the browser from sending credentials (cookies) automatically. The body of the response is still readable by any origin. That means:

- If the API is `/api/user` and returns the user's profile data when authenticated via a header-borne token, any malicious site can post the token to its own page and read the profile.
- If the API uses cookies and the developer adds `Access-Control-Allow-Credentials: true` alongside the wildcard (which browsers should refuse, but some implementations ship anyway), every cross-origin site reads cookie-authenticated responses.

The pattern shows up most in vibe-built APIs because "fix the CORS error" tutorials default to wildcard.

## What the failure looks like

PreFlight scans server-side code for:

```js
res.setHeader('Access-Control-Allow-Origin', '*');
res.headers.set('Access-Control-Allow-Origin', '*');
'Access-Control-Allow-Origin': '*'
```

In any common Node / Express / Next.js / Hono / Cloudflare Worker shape.

## What the fix looks like

Replace the wildcard with an explicit allowlist:

```ts
const ALLOWED_ORIGINS = new Set(['https://app.example.com', 'https://example.com']);

export async function handler(req: Request) {
  const origin = req.headers.get('origin');
  const headers = new Headers();
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.set('Vary', 'Origin');
  }
  headers.set('Access-Control-Allow-Methods', 'GET, POST');
  headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  // ...
}
```

Three rules:

- Never wildcard for authenticated endpoints. Either explicit allowlist or refuse the cross-origin call.
- Always set `Vary: Origin` when echoing the origin back. Without it, intermediate caches will serve one origin's response to another origin's requests.
- Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. The combination is invalid per spec; some servers ship it anyway and some browsers honor it; the result is a worst-of-both.

## Related

- [Security headers](/learn/patterns/security-headers) covers the broader response-header hardening.
- [API route auth](/learn/patterns/api-route-auth) covers the underlying auth checks CORS sits on top of.

## Sources

MDN's CORS doc is the authoritative reference. OWASP's CSRF prevention cheat sheet covers the related cross-origin attack pattern. CWE-942 names the vulnerability class.
