---
title: Missing security headers
slug: security-headers
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Security Headers
sources:
  - title: OWASP Secure Headers Project
    url: https://owasp.org/www-project-secure-headers/
  - title: MDN — Content Security Policy (CSP)
    url: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
  - title: MDN — X-Frame-Options
    url: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
  - title: MDN — Strict-Transport-Security
    url: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
summary: Production deploys that don't set CSP, X-Frame-Options, Strict-Transport-Security, and Referrer-Policy leave defense-in-depth controls off. Each header blocks a specific class of attack at the browser level.
---

## What this is

Security headers are HTTP response headers the browser uses to decide what loaded code is allowed to do. The relevant ones:

- **`Content-Security-Policy`** (CSP). Whitelists script, image, style, and fetch sources. Blocks the bulk of XSS impact even when an XSS landed.
- **`Strict-Transport-Security`** (HSTS). Forces HTTPS for the domain. Defeats downgrade attacks.
- **`X-Frame-Options`** or CSP `frame-ancestors`. Prevents the page from being embedded in an attacker's iframe (clickjacking defense).
- **`X-Content-Type-Options: nosniff`**. Prevents the browser from guessing MIME types, which blocks a class of cross-content attacks.
- **`Referrer-Policy`**. Controls what URL information goes out in the `Referer` header on outbound requests.
- **`Permissions-Policy`**. Whitelists browser APIs (geolocation, camera, microphone, USB) for the page.

A production deploy without these headers is operating with the browser-level defense layer turned off. Application-layer bugs that would have been bounded become unbounded.

## Why it matters

Headers do not prevent vulnerabilities; they bound the blast radius. A reflected XSS on a page with strict CSP can run only what CSP allows, which is usually nothing useful to an attacker. The same XSS on a page with no CSP runs anywhere it lands.

Missing HSTS exposes users to network-level downgrade attacks. Missing X-Frame-Options exposes the site to clickjacking (a page embedded in an iframe with the user's session attached). Missing nosniff exposes users to MIME-confusion attacks where an uploaded file gets executed as HTML.

## What the failure looks like

PreFlight checks the canonical config locations:

- Next.js: `headers()` function in `next.config.js` / `next.config.mjs`.
- Vercel: `headers` array in `vercel.json`.
- Cloudflare Pages: `_headers` file in the public directory.
- Express / Node: `helmet` middleware usage or equivalent manual `res.setHeader` calls.

Absence of any of the canonical configurations is a finding.

## What the fix looks like

**For Next.js (App Router):**

```js
// next.config.mjs
export default {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          {
            key: 'Content-Security-Policy',
            value:
              "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://api.example.com",
          },
        ],
      },
    ];
  },
};
```

**For Cloudflare Pages**, ship a `public/_headers` file:

```
/*
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Content-Security-Policy: default-src 'self'; script-src 'self'
```

**For Express:**

```js
import helmet from 'helmet';
app.use(helmet());
```

CSP is the one to tune carefully. Too-strict and the app breaks. Too-loose and the header is decorative. The standard approach is to write a working policy in `Content-Security-Policy-Report-Only` mode first, watch the reports for a week, then promote to enforcement.

## Related

- [HTML hygiene](/learn/patterns/html-hygiene) covers the inline-handler and inline-script patterns that a strict CSP refuses to run.
- [CORS](/learn/patterns/cors) covers the cross-origin access control layer that often gets misconfigured alongside.

## Sources

The OWASP Secure Headers Project is the authoritative reference for which headers to set and how. MDN's CSP, HSTS, and X-Frame-Options docs cover each header in depth.
