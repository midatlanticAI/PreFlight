---
title: SSRF and open redirects
slug: ssrf-open-redirect
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - SSRF / Open Redirect
sources:
  - title: OWASP A10 — Server-Side Request Forgery (SSRF)
    url: https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
  - title: OWASP — Unvalidated Redirects and Forwards Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
  - title: CWE-918 — Server-Side Request Forgery (SSRF)
    url: https://cwe.mitre.org/data/definitions/918.html
  - title: CWE-601 — URL Redirection to Untrusted Site
    url: https://cwe.mitre.org/data/definitions/601.html
summary: Two related patterns: SSRF (server fetches a URL the client supplies; attacker uses the server to talk to private networks) and open redirect (server redirects the user to a URL the client supplies; attacker uses the trusted domain for phishing).
---

## What this is

**Open redirect** (CWE-601):

```ts
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const next = searchParams.get('next');
  return Response.redirect(next); // attacker controls `next`
}
```

A login flow with `?next=/dashboard` is normal. An attacker sends a victim a link like `https://yourapp.com/login?next=https://attacker-phishing.example/`. The user logs in (recognizing the real domain), then gets redirected to the phishing site (still seeming legitimate because the redirect was issued by the real domain).

**SSRF** (CWE-918):

```ts
export async function POST(req: Request) {
  const { url } = await req.json();
  const r = await fetch(url); // server fetches whatever the client says
  return Response.json(await r.text());
}
```

An attacker submits `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/`. That endpoint serves AWS instance credentials when called from inside the instance's network. The server runs the fetch from inside the instance's network. The credentials come back. The attacker has cloud creds.

## Why it matters

**Open redirect:** the trust the domain holds with users (phishing detection, browser warnings, password manager autofill) is transferred to the attacker's destination for the duration of the redirect. Antivirus and phishing-detection systems whitelist the original domain. Users trust links from people they know.

**SSRF:** the server has network access the attacker does not. Internal services, cloud metadata endpoints, container orchestration APIs, and intranet resources are all reachable from inside the network. An attacker who can make the server issue a request to an arbitrary URL has read access to all of them.

## What the failure looks like

PreFlight scans server-side code for:

- `res.redirect(<expr>)` where the expression traces back to `req.body`, `req.query`, or `req.params`.
- `fetch(<expr>)` (or `axios.get(<expr>)`, `request(...)`, etc.) where the URL traces back to user input.

## What the fix looks like

**Open redirect:** allowlist the destination.

```ts
const ALLOWED_PATHS = /^\/[a-zA-Z0-9_\-\/]*$/; // internal paths only

export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const next = searchParams.get('next');
  const safe = ALLOWED_PATHS.test(next || '') ? next : '/';
  return Response.redirect(new URL(safe, req.url));
}
```

If the redirect must go to external URLs (OAuth callbacks, payment processor returns), allowlist the specific domains:

```ts
const ALLOWED_HOSTS = new Set(['accounts.google.com', 'github.com', 'auth.example.com']);

const target = new URL(next);
if (!ALLOWED_HOSTS.has(target.hostname)) {
  return new Response('Invalid redirect', { status: 400 });
}
```

**SSRF:** validate the destination before issuing the fetch. Block private IP ranges, the cloud metadata endpoint, and localhost.

```ts
import dns from 'node:dns/promises';
import net from 'node:net';

const BLOCKED_HOSTS = new Set(['169.254.169.254', 'metadata.google.internal']);
const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^0\./,
  /^::1$/,
  /^fc/,
  /^fe80:/,
];

async function isSafeUrl(input: string): Promise<boolean> {
  const u = new URL(input);
  if (!['http:', 'https:'].includes(u.protocol)) return false;
  if (BLOCKED_HOSTS.has(u.hostname)) return false;
  const addrs = await dns.resolve(u.hostname);
  return addrs.every((a) => !PRIVATE_RANGES.some((re) => re.test(a)));
}

export async function POST(req: Request) {
  const { url } = await req.json();
  if (!(await isSafeUrl(url))) return new Response('Invalid URL', { status: 400 });
  const r = await fetch(url);
  return Response.json(await r.text());
}
```

Better, when the API can be designed around it: take a domain enum instead of an arbitrary URL. `{ provider: 'github', path: '/user' }` gets mapped server-side to `https://api.github.com/user`. The client never specifies a host.

## Related

- [URL reputation](/learn/patterns/url-reputation) covers the broader class of "URL referenced in source" findings, which often catch SSRF destinations.
- [API route auth](/learn/patterns/api-route-auth) covers the authorization layer that should gate SSRF-capable endpoints in the first place.

## Sources

OWASP A10:2021 ranks SSRF as a top-10 risk. The OWASP unvalidated-redirects cheat sheet covers the open-redirect side. CWE-918 and CWE-601 name the two classes.
