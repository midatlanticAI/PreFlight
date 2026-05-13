---
title: Subresource Integrity (SRI) on third-party scripts
slug: subresource-integrity
type: pattern
last_updated: 2026-05-12
draft: false
related_probe_ids:
  - Subresource Integrity
  - HTML Hygiene
sources:
  - title: 'MDN — Subresource Integrity'
    url: https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity
  - title: 'W3C — Subresource Integrity'
    url: https://www.w3.org/TR/SRI/
  - title: 'CWE-353 — Missing Support for Integrity Check'
    url: https://cwe.mitre.org/data/definitions/353.html
  - title: 'OWASP A08 — Software and Data Integrity Failures'
    url: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
summary: A `<script src="https://cdn.example/library.js">` without `integrity="sha384-..."` trusts the CDN unconditionally. SRI is the browser-level guarantee that the asset has not been tampered with between deploy and load.
---

## What this is

```html
<!-- Trust the CDN forever. -->
<script src="https://cdn.example.com/some-library@1.0.0/dist/library.js"></script>
```

When the browser fetches that URL, it executes whatever the CDN returns. If the CDN is compromised, the page runs the compromised version. The same is true for any subsequent request: the CDN can serve different content next time and the browser will run that.

```html
<!-- Trust verified at load time. -->
<script
  src="https://cdn.example.com/some-library@1.0.0/dist/library.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
  crossorigin="anonymous"
></script>
```

The `integrity` attribute is a hash of the expected file content. The browser fetches the asset, computes the hash, and refuses to execute if the hash does not match. A compromised CDN serving a hostile script gets blocked at the browser level before any code runs.

## Why it matters

CDN compromises happen. Polyfill.io, JSDelivr packages, and CDNJS-hosted libraries have all had documented incidents. A site that pulls third-party JS without SRI is running whatever the CDN serves at the moment of the request, including any maliciously-substituted content.

The blast radius equals the page's full JavaScript capability: every API the page makes, every cookie not marked HttpOnly, every form the user submits, every credential typed into the page.

SRI is the cheapest defense available against this class. The hash is computed once at deploy time, written into the HTML, and the browser does the rest.

## What the failure looks like

Pre-Flight scans HTML, JSX, TSX, Astro, Vue, and Svelte files for:

- `<script>` tags with a cross-origin `src` attribute (any URL starting with `http://`, `https://`, or `//`) and no `integrity` attribute.
- `<link rel="stylesheet">` tags with a cross-origin `href` attribute and no `integrity` attribute.

Same-origin scripts (relative paths, absolute paths starting with `/`) are not flagged. SRI is not required for first-party assets where the deploy pipeline already controls the bytes.

## What the fix looks like

**Generate the integrity hash at build time.**

Most build tools have plugins or built-in support. For Vite, `vite-plugin-sri`. For webpack, `webpack-subresource-integrity`. For Astro, the integrity plugin auto-adds hashes to every cross-origin asset.

**Or compute manually for a small number of pinned scripts.**

```bash
curl https://cdn.example.com/some-library@1.0.0/dist/library.js |
  openssl dgst -sha384 -binary |
  openssl base64 -A
```

The output is the value for `integrity="sha384-..."`. Pin the version in the URL so the hash is stable.

**Required companion: `crossorigin="anonymous"`.**

```html
<script
  src="https://cdn.example.com/library.js"
  integrity="sha384-..."
  crossorigin="anonymous"
></script>
```

`crossorigin="anonymous"` tells the browser to make the request without credentials, which is required for SRI to work on cross-origin loads. Without it, the browser still loads the script but skips the integrity check.

**For CDNs that publish the hash:**

Most reputable CDNs (jsdelivr, cdnjs, esm.sh) publish the SRI hash next to the version on their package page. Copy it. If the CDN does not publish hashes, self-host the asset (the third-party JS becomes a same-origin asset in your `public/` folder).

## Cases where SRI does not apply

- Same-origin scripts (no SRI needed; you control the bytes).
- Scripts loaded by other scripts at runtime (SRI is for the initial HTML-level tag; dynamic imports need a different defense).
- CDNs that serve dynamically-generated or per-user content (the hash would change per request; SRI cannot verify it).

For the second case (dynamic loaders like `import()`), the defense is to keep the loader's source on first-party origin and SRI-protect the loader itself.

For the third case, the answer is usually to move that surface off the CDN model entirely.

## Related

- [HTML hygiene](/learn/patterns/html-hygiene) covers the broader HTML-quality layer; SRI is one specific check in that surface.
- [Security headers](/learn/patterns/security-headers) covers the CSP that complements SRI.
- [package.json supply-chain hooks](/learn/patterns/package-json-supply-chain) is the npm-side equivalent of CDN compromise.

## Sources

MDN's SRI doc is the practitioner reference. The W3C SRI spec is the underlying standard. CWE-353 names the integrity-check class. OWASP A08:2021 covers software and data integrity failures, which is the broader category SRI mitigates.
